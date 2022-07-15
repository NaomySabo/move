// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{sandbox::utils::module, DEFAULT_BUILD_DIR, DEFAULT_STORAGE_DIR, sandbox};

use move_command_line_common::{
    env::read_bool_env_var,
    files::{path_to_string},
    testing::{format_diff, read_env_update_baseline, EXP_EXT},
};
use move_compiler::command_line::COLOR_MODE_ENV_VAR;
use move_coverage::summary::{summarize_inst_cov_by_module};
use move_coverage::coverage_map::{CoverageMap, ExecCoverageMapWithModules};
use move_package::{
    compilation::{compiled_package::OnDiskCompiledPackage, package_layout::CompiledPackageLayout},
    source_package::{layout::SourcePackageLayout, manifest_parser::parse_move_manifest_from_file},
};
use std::{
    collections::{BTreeMap, HashMap},
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    process::Command,
};
use std::collections::HashSet;
use sandbox::commands::test::{
    copy_deps,
    simple_copy_dir
};
use coinflip;
use tempfile::tempdir;
use move_binary_format::internals::ModuleIndex;
use move_binary_format::file_format::SignatureToken::{Bool, Signer, U128, U8, U64, Address};
use move_binary_format::file_format::SignatureToken::Reference;
// use move_binary_format::file_format::Visibility::Script;
use move_core_types::account_address::AccountAddress;
use rand::distributions::{Distribution};
use priority_queue::PriorityQueue;
use move_binary_format::file_format::SignatureToken;
use rand::{Rng};


/// Basic datatest testing framework for the CLI. The `run_one` entrypoint expects
/// an `args.txt` file with arguments that the `move` binary understands (one set
/// of arguments per line). The testing framework runs the commands, compares the
/// result to the expected output, and runs `move clean` to discard resources,
/// modules, and event data created by running the test.

/// If this env var is set, `move clean` will not be run after each test.
/// this is useful if you want to look at the `storage` or `move_events`
/// produced by a test. However, you'll have to manually run `move clean`
/// before re-running the test.
const NO_MOVE_CLEAN: &str = "NO_MOVE_CLEAN";

/// The filename that contains the arguments to the Move binary.
pub const TEST_ARGS_FILENAME: &str = "args.txt";

/// Name of the environment variable we need to set in order to get tracing
/// enabled in the move VM.
const MOVE_VM_TRACING_ENV_VAR_NAME: &str = "MOVE_VM_TRACE";

/// The default file name (inside the build output dir) for the runtime to
/// dump the execution trace to. The trace will be used by the coverage tool
/// if --track-cov is set. If --track-cov is not set, then no trace file will
/// be produced.
const DEFAULT_TRACE_FILE: &str = "trace";

pub struct TestTemplate {
    mod_addr: AccountAddress,
    mod_name: String,
    func_name: String,
    params: Vec<move_binary_format::file_format::SignatureToken>
}

// fn print_type_of<T>(_: &T) -> &str {
//     println!("{}", std::any::type_name::<T>());
//     return std::any::type_name::<T>();
// }

fn collect_coverage(
    trace_file: &Path,
    build_dir: &Path,
) -> anyhow::Result<ExecCoverageMapWithModules> {
    let canonical_build = build_dir.canonicalize().unwrap();

    let package_name = parse_move_manifest_from_file(
        &SourcePackageLayout::try_find_root(&canonical_build).unwrap(),
    )?
        .package
        .name
        .to_string();
    let pkg = OnDiskCompiledPackage::from_path(
        &build_dir
            .join(package_name)
            .join(CompiledPackageLayout::BuildInfo.path()),
    )?
        .into_compiled_package()?;
    let src_modules = pkg
        .all_modules()
        .map(|unit| {
            let absolute_path = path_to_string(&unit.source_path.canonicalize()?)?;
            Ok((absolute_path, module(&unit.unit)?.clone()))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()?;

    // build the filter
    let mut filter = BTreeMap::new();
    for (entry, module) in src_modules.into_iter() {
        let module_id = module.self_id();
        filter
            .entry(*module_id.address())
            .or_insert_with(BTreeMap::new)
            .insert(module_id.name().to_owned(), (entry, module));
    }

    // collect filtered trace
    let coverage_map = CoverageMap::from_trace_file(trace_file)
        .to_unified_exec_map()
        .into_coverage_map_with_modules(filter);



    let path = "coverage_map";
    let mut output = File::create(path)?;
    write!(output, "{:#?}", coverage_map).expect("Failed to write to coverage map file");

    Ok(coverage_map)
}

/// Run the `args_path` batch file with`cli_binary`
pub fn run_one(
    args_path: &Path,
    cli_binary: &Path,
    use_temp_dir: bool,
) -> anyhow::Result<(Option<ExecCoverageMapWithModules>, bool)> {

    let args_file = io::BufReader::new(File::open(args_path)?).lines();
    let cli_binary_path = cli_binary.canonicalize()?;

    // path where we will run the binary
    let exe_dir = args_path.parent().unwrap();
    let temp_dir = if use_temp_dir {
        // symlink everything in the exe_dir into the temp_dir
        let dir = tempdir()?;
        let padded_dir = copy_deps(dir.path(), exe_dir)?;
        simple_copy_dir(&padded_dir, exe_dir)?;
        Some((dir, padded_dir))
    } else {
        None
    };
    let wks_dir = temp_dir.as_ref().map_or(exe_dir, |t| &t.1);

    let storage_dir = wks_dir.join(DEFAULT_STORAGE_DIR);
    let build_output = wks_dir
        .join(DEFAULT_BUILD_DIR)
        .join(CompiledPackageLayout::Root.path());

    // template for preparing a cli command
    let cli_command_template = || {
        let mut command = Command::new(cli_binary_path.clone());
        if let Some(work_dir) = temp_dir.as_ref() {
            command.current_dir(&work_dir.1);
        } else {
            command.current_dir(exe_dir);
        }
        command
    };

    if storage_dir.exists() || build_output.exists() {
        // need to clean before testing
        cli_command_template()
            .arg("sandbox")
            .arg("clean")
            .output()?;
    }
    let mut output = "".to_string();

    // always use the absolute path for the trace file as we may change dirs in the process
    let trace_file = Some(wks_dir.canonicalize()?.join(DEFAULT_TRACE_FILE));

    // Disable colors in error reporting from the Move compiler
    env::set_var(COLOR_MODE_ENV_VAR, "NONE");
    let mut error_present = false;

    for args_line in args_file {
        let args_line = args_line?;

        if args_line.starts_with('#') {
            // allow comments in args.txt
            continue;
        }
        let args_iter: Vec<&str> = args_line.split_whitespace().collect();
        if args_iter.is_empty() {
            // allow blank lines in args.txt
            continue;
        }

        // enable tracing in the VM by setting the env var.
        match &trace_file {
            None => {
                env::remove_var(MOVE_VM_TRACING_ENV_VAR_NAME);
            }
            Some(path) => env::set_var(MOVE_VM_TRACING_ENV_VAR_NAME, path.as_os_str()),
        }

        let cmd_output = cli_command_template().args(args_iter).output()?;

        output += &format!("Command `{}`:\n", args_line);
        output += std::str::from_utf8(&cmd_output.stdout)?;
        output += std::str::from_utf8(&cmd_output.stderr)?;

        // Check to see if any of the commands ran generated any errors
        if std::str::from_utf8(&cmd_output.stdout)?.contains(&"error") ||
            !std::str::from_utf8(&cmd_output.stderr)?.is_empty() {
            error_present = true;
        }
    }

    // collect coverage information
    let cov_info = match &trace_file {
        None => None,
        Some(trace_path) => {
            if trace_path.exists() {
                Some(collect_coverage(trace_path, &build_output)?)
            } else {
                let file_path = PathBuf::from(trace_path);
                std::fs::write(file_path, "").expect("failed to write coverage");
                Some(collect_coverage(trace_path, &build_output)?)
            }
        }
    };

    // post-test cleanup and cleanup checks
    // check that the test command didn't create a src dir
    let run_move_clean = !read_bool_env_var(NO_MOVE_CLEAN);
    if run_move_clean {
        // run the clean command to ensure that temporary state is cleaned up
        cli_command_template()
            .arg("sandbox")
            .arg("clean")
            .output()?;

        // check that build and storage was deleted
        assert!(
            !storage_dir.exists(),
            "`move clean` failed to eliminate {} directory",
            DEFAULT_STORAGE_DIR
        );
        assert!(
            !build_output.exists(),
            "`move clean` failed to eliminate {} directory",
            DEFAULT_BUILD_DIR
        );

        // clean the trace file as well if it exists
        // if let Some(trace_path) = &trace_file {
        //     if trace_path.exists() {
        //         // fs::remove_file(trace_path)?;
        //     }
        // }
    }

    // release the temporary workspace explicitly
    if let Some((t, _)) = temp_dir {
        t.close()?;
    }

    // compare output and exp_file
    let update_baseline = read_env_update_baseline();
    let exp_path = args_path.with_extension(EXP_EXT);
    if update_baseline {
        fs::write(exp_path, &output)?;
        return Ok((cov_info, error_present));
    }

    let expected_output = fs::read_to_string(exp_path).unwrap_or_else(|_| "".to_string());

    if expected_output != output {
        anyhow::bail!(
            "Expected output differs from actual output:\n{}",
            format_diff(expected_output, output)
        )
    } else {
        Ok((cov_info, error_present))
    }
}

pub fn start_fuzz(
    exe_dir: &Path,
    cli_binary: &Path,
    use_temp_dir: bool,
    test_name: &str
) -> Result<Vec<TestTemplate>, anyhow::Error> {
// HashMap<std::string::String, CompiledModule> {

    let cli_binary_path = cli_binary.canonicalize()?;

    let temp_dir = if use_temp_dir {
        // symlink everything in the exe_dir into the temp_dir
        let dir = tempdir()?;
        let padded_dir = copy_deps(dir.path(), exe_dir)?;
        simple_copy_dir(&padded_dir, exe_dir)?;
        Some((dir, padded_dir))
    } else {
        None
    };
    let wks_dir = temp_dir.as_ref().map_or(exe_dir, |t| &t.1);


    let storage_dir = wks_dir.join(DEFAULT_STORAGE_DIR);
    let build_output = wks_dir
        .join(DEFAULT_BUILD_DIR)
        .join(CompiledPackageLayout::Root.path());

    // template for preparing a cli command
    let cli_command_template = || {
        let mut command = Command::new(cli_binary_path.clone());
        if let Some(work_dir) = temp_dir.as_ref() {
            command.current_dir(&work_dir.1);
        } else {
            command.current_dir(exe_dir);
        }
        command
    };

    if storage_dir.exists() || build_output.exists() {
        // need to clean before testing
        cli_command_template()
            .arg("sandbox")
            .arg("clean")
            .output()?;
    }
    // always use the absolute path for the trace file as we may change dirs in the process
    let trace_file = Some(wks_dir.canonicalize()?.join(DEFAULT_TRACE_FILE));
    // match &trace_file {
    //     Some(path) => env::set_var(MOVE_VM_TRACING_ENV_VAR_NAME, path.as_os_str()),
    // }
    // env::set_var(MOVE_VM_TRACING_ENV_VAR_NAME, path.as_os_str());

    // Disable colors in error reporting from the Move compiler
    env::set_var(COLOR_MODE_ENV_VAR, "NONE");

    cli_command_template().arg("package").arg("build").output()?;
    cli_command_template().arg("sandbox").arg("publish").output()?;
    let mut tests: Vec<TestTemplate> = Vec::new();

    match &trace_file {
        None => None,
        Some(trace_path) => {
            let file_path = PathBuf::from(trace_path);
            std::fs::write(file_path, "").expect("couldn't write coverage to tracefile");

            let canonical_build = &build_output.canonicalize().unwrap();
            let package_name = parse_move_manifest_from_file(
                &SourcePackageLayout::try_find_root(&canonical_build).unwrap(),
            )?.package.name.to_string();

            let pkg = OnDiskCompiledPackage::from_path(
                &&build_output
                    .join(package_name)
                    .join(CompiledPackageLayout::BuildInfo.path()),
            )?
                .into_compiled_package()?;
            let src_modules = pkg
                .all_modules()
                .map(|unit| {
                    let absolute_path = path_to_string(&unit.source_path.canonicalize()?)?;
                    Ok((absolute_path, module(&unit.unit)?.clone()))
                })
                .collect::<anyhow::Result<HashMap<_, _>>>()?;
            // OK(&src_modules);
            // return src_modules;
            for (entry, info) in &src_modules {
                // let module_id = module.self_id();
                // println!("{:#?}", entry.clone());
                // if !entry.contains("dependencies") {
                // TODO: concat /
                if entry.ends_with(test_name) {
                    // Import the modules to be fuzzed in the test script
                    for f_def in &info.function_defs {
                        // if f_def.visibility == Script {
                        // Obtain the function name from the coverage map
                        let func = &info.function_handles[f_def.function.into_index()];
                        let name_idx = func.name.into_index();
                        let func_name: String = info.identifiers[name_idx].as_str().to_owned();

                        // Obtain the function signature from the coverage map
                        let param_idx = func.parameters.into_index();
                        let parameters = &info.signatures[param_idx].0;

                        let mod_idx = func.module.into_index();
                        let id_idx = info.module_handles[mod_idx].name.into_index();
                        let module: String = info.identifiers[id_idx].as_str().to_owned();

                        let addr_idx = info.module_handles[mod_idx].address.into_index();
                        let mod_addr = info.address_identifiers[addr_idx];

                        let test = TestTemplate {
                            mod_addr,
                            mod_name: module,
                            func_name,
                            params: parameters.to_vec()
                        };
                        tests.push(test)
                        // }
                    }

                }
            }
            Some(trace_path)
        }
    };

    // post-test cleanup and cleanup checks
    // run the clean command to ensure that temporary state is cleaned up
    cli_command_template().arg("sandbox").arg("clean").output()?;

    // check that build and storage was deleted
    assert!(
        !storage_dir.exists(),
        "`move clean` failed to eliminate {} directory",
        DEFAULT_STORAGE_DIR
    );
    assert!(
        !build_output.exists(),
        "`move clean` failed to eliminate {} directory",
        DEFAULT_BUILD_DIR
    );

    // release the temporary workspace explicitly
    if let Some((t, _)) = temp_dir {
        t.close()?;
    }

    Ok(tests)
}

pub fn get_signer() -> String {
    // One hex = 2^4 = 4 bits = 1/2 byte
    // Two hex = 2^8 = 8 bits = 1 byte
    let address_bits = vec![
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"
    ];

    let range = rand::distributions::Uniform::from(1..16);
    let mut rng = rand::thread_rng();
    let mut signer: String = "0x".to_string();
    for _i in 0..32 {
        let addr_bit = range.sample(&mut rng);
        signer = signer.clone() + address_bits[addr_bit];
    }
    signer
}




pub fn fuzz_int(int_type: &SignatureToken) -> String {
    // Flip a coin to see whether to test with an "edge" value, or generate a random value
    let mut rng = rand::thread_rng();
    let special_nums_u8: Vec<u8> = vec![0, 1, u8::MAX-1, u8::MAX];
    let special_nums_u64: Vec<u64> = vec![0, 1, u64::MAX-1, u64::MAX];
    let special_nums_u128: Vec<u128> = vec![0, 1, u128::MAX-1, u128::MAX];

    if coinflip::flip() {
        // Random number generator to choose which special value is selected
        let between = rand::distributions::Uniform::from(0..4);
        let idx = between.sample(&mut rng);

        if int_type == &U8 {
            special_nums_u8[idx].to_string()
        } else if int_type == &U64 {
            special_nums_u64[idx].to_string()
        } else {
            special_nums_u128[idx].to_string()
        }
        // Otherwise choose a random number
    } else if int_type == &U8 {
        let rand_num = rng.gen_range(2..u8::MAX-1);
        rand_num.to_string()
    } else if int_type == &U64 {
        let rand_num = rng.gen_range(2..u64::MAX-1);
        rand_num.to_string()
    } else {
        let rand_num = rng.gen_range(2..u128::MAX-1);
        rand_num.to_string()
    }

}

pub fn fuzz_inputs(
    f: &TestTemplate,
    mut output: &File,
    module_signer: String
) -> anyhow::Result<()> {
    let mut t : String = "sandbox run storage/0x".to_owned() +
        &f.mod_addr.to_string() +
        "/modules/" + &f.mod_name.to_string() + ".mv ";

    let mut signer_pres = false;
    let mut args_pres = false;
    let mut args = Vec::new();

    for (_i, p) in f.params.iter().enumerate() {

        if p == &Reference(Box::new(Signer)) || *p == Signer {
            signer_pres = true;
        } else {
            args_pres = true;

            // /// Boolean, `true` or `false`.
            // Bool,
            // /// Unsigned integers, 8 bits length.
            // U8,
            // /// Unsigned integers, 64 bits length.
            // U64,
            // /// Unsigned integers, 128 bits length.
            // U128,
            // /// Address, a 16 bytes immutable type.
            // TODO: Address,
            // /// Signer, a 16 bytes immutable type representing the capability to publish at an address

            if p == &U8 || p == &U64 || p == &U128 {
                // args.push("12345678");
                args.push(fuzz_int(p))
            } else if p == &Bool {
                args.push(coinflip::flip().to_string())
            } else if *p == Address || p == &Address {
                args.push(module_signer.clone())
            }
        }
    }

    if signer_pres {
        // let module_signer = get_signer();
        t += &("--signers ".to_owned() + &module_signer + " ");
    }
    if args_pres {
        t += "--args ";
        for a in args {
            t += &(a.to_owned() + " ");
        }
    }
    t += "-v ";
    t += &f.func_name;

    writeln!(output, "{}", t).expect("Failed to write to args file");
    Ok(())
}

pub fn move_tests(test_path: &String, folder_type: String) -> Result<String, anyhow::Error> {
    let mut folder = "tests-error/";
    if folder_type == "RAN" {
        folder = "tested/";
    } else if folder_type == "NOT_RAN" {
        folder = "not-tested/";
    }

    let test_name = "fuzz-tests/".to_owned() + folder + test_path;

    // Create a file in the error folder to copy the test to
    File::create(&test_name)?;

    // Copy the test and corresponding exp file to the tests-error directory
    fs::copy(&test_path, &test_name)?;

    // Delete the original test and exp file
    fs::remove_file(&test_path)?;

    if folder_type != "NOT_RAN" {
        // In these cases, there is also a .exp file we need to get rid of for the test
        let exp_name = "fuzz-tests/".to_owned() + folder + test_path + ".exp";
        let exp_path = test_path.to_owned() + ".exp";
        // Create a file in the correct folder to copy the .exp file to
        File::create(&exp_name)?;
        // Copy the exp file to the correct directory
        fs::copy(&exp_path, &exp_name)?;
        // Delete the original exp file
        fs::remove_file(&exp_path)?;
    }

    Ok(test_name)
}

pub fn fuzzer(
    args_path: &Path,
    cli_binary: &Path,
    use_temp_dir: bool,
    // This is the name of the file whose functions are to be tested
    test_name: &str
) -> anyhow::Result<()> {
    let mut test_total: u64 = 0;
    let mut test_passed: u64 = 0;

    // Create a directory to store the output tests of our fuzzer
    let fuzz_path = Path::new("fuzz-tests");
    fs::create_dir(fuzz_path).expect("Failed to create fuzz tests directory");
    if let Some(p) = fuzz_path.parent() { fs::create_dir_all(p)? };

    // Create a subdirectory for tests that invoke errors in the target program
    let error_path = Path::new("fuzz-tests/tests-error");
    fs::create_dir(error_path).expect("Failed to create the error test directory");
    if let Some(p) = error_path.parent() { fs::create_dir_all(p)? };

    // Create a subdirectory for tests that have been run
    let ran_path = Path::new("fuzz-tests/tested");
    fs::create_dir(ran_path).expect("Failed to create the tested directory");
    if let Some(p) = ran_path.parent() { fs::create_dir_all(p)? };

    // Create a subdirectory for tests that have not been run
    let ran_path = Path::new("fuzz-tests/not-tested");
    fs::create_dir(ran_path).expect("Failed to create the not tested directory");
    if let Some(p) = ran_path.parent() { fs::create_dir_all(p)? };

    // Returns an array of function templates (module name, function name, parameters and module address)
    let template = start_fuzz(args_path, cli_binary, use_temp_dir, test_name).unwrap();

    // This will be used to keep track of the number of tests created
    let mut count = 0;

    // This will store the file paths to any test files created
    let mut test_paths: Vec<String> = Vec::new();

    // This will keep track of any signers used so far
    let mut signers: Vec<String> = vec![get_signer()];

    // For each of the eligible functions in the library, push an initial test for it to test_paths, 
    // from which we will form our queue
    for func in template.iter() {
        let new_test = format!("test{}", count);
        let mut output = File::create(&new_test)?;

        // First line in each test should be "sandbox publish"
        writeln!(output, "sandbox publish").expect("Failed to write to args file");

        // This will write some tests into our testfile
        fuzz_inputs(&func, &output, signers[0].clone()).unwrap();
        test_paths.push(new_test);
        count += 1;
    }

    // This queue holds the names of the test files. Tests will be popped from this queue, ran, 
    // and if they receive positive feedback, then a mutated version will be pushed to the back 
    // of the queue. Once ran, all tests will be moved to the "used" test directory under the fuzz-tests
    // folder that is generated when running the fuzz cli command.
    // let mut deque = VecDeque::from(test_paths);
    let mut pq = PriorityQueue::new();
    for test in test_paths {
        pq.push(test, 100);
    }

    // Random number generator to choose which function
    let between = rand::distributions::Uniform::from(0..template.len());
    let mut rng = rand::thread_rng();

    let mut cov_info = ExecCoverageMapWithModules::empty();
    let mut covered: HashMap<String, u64> = HashMap::new();
    let mut tests_ran: HashSet<String> = HashSet::new();
    // TODO: HASH SET !!!!!


    let mut b = 0;
    while !pq.is_empty()
        && b < 40
    {
        b += 1;
        let seed = pq.pop();
        let clone = seed.clone();
        match seed {
            Some(test_path)   => {
                if tests_ran.contains(&test_path.0) {
                    println!("{:#?} mutated now into test {}", &test_path.0, count);

                    //Regardless if the test generated new coverage, mutate it and add a new version to our queue
                    let new_test = format!("test{}", count);
                    count += 1;

                    // Copy the calls in the old test to the new test
                    fs::copy(&test_path.0, &new_test).expect("Could not create new test from old test");

                    let file = OpenOptions::new().write(true).append(true).open(&new_test).unwrap();

                    // Add a new function call to the new test
                    // a) Randomly select which function to add
                    let idx = between.sample(&mut rng);
                    // b) Write a function call for the randomly selected function to the new test
                    let generate_new = coinflip::flip();
                    if generate_new {
                        let new_signer = get_signer();
                        fuzz_inputs(&template[idx], &file, new_signer.clone()).expect("could not write to new test");
                        signers.push(new_signer);
                    } else {
                        fuzz_inputs(&template[idx], &file, signers[0].clone()).expect("could not write to new test");
                    }

                    // Push the new test to the queue
                    pq.push(new_test, test_path.1 + 1);
                    // Push the old test to the queue
                    pq.push(test_path.0.to_string(), test_path.1 -1);

                } else {
                    match run_one(Path::new(&("./".to_owned() + &test_path.0)), cli_binary, use_temp_dir) {
                        Ok(tuple) => {
                            tests_ran.insert(test_path.clone().0);

                            test_total = test_total.checked_add(1).unwrap();
                            test_passed = test_passed.checked_add(1).unwrap();

                            if let Some(cov) = tuple.0 {
                                cov_info.merge(cov);
                            }

                            let is_error = tuple.1;
                            if is_error {
                                //move this test to the error folder
                                move_tests(&test_path.0, "ERROR".to_string()).
                                    expect("Failed to move test to the error folder");
                                // Remove this test from our queue
                                println!("{:#?} gave an error", &test_path.0);
                                let compiled_modules = &cov_info.compiled_modules;

                                for i in &cov_info.module_maps {
                                    let module_summary = summarize_inst_cov_by_module(
                                        compiled_modules.get(&i.0.0).unwrap(),
                                        Some(&i.1),
                                    );

                                    for (fn_name, fn_summary) in module_summary.function_summaries.iter() {
                                        let mod_func = module_summary.module_name.name().as_str().to_string() + &fn_name.to_string();
                                        if covered.contains_key(&mod_func) {
                                            // Check if we have more coverage for the function
                                            if fn_summary.covered > *covered.get(&mod_func).unwrap() {
                                                println!("{:#?} had an error, but gave new coverage in function: {:#?}", &test_path.0, &mod_func);
                                                *covered.get_mut(&mod_func).unwrap() = fn_summary.covered;
                                            }
                                        } else if fn_summary.covered > 0 {
                                            // This means that the current test reached a function that wasn't covered before
                                            println!("{:#?} had an error, but reached this function for the first time: {:#?}", &test_path.0, &mod_func);
                                            covered.insert(mod_func, fn_summary.covered);
                                        }

                                        // match covered.entry(mod_func.clone()) {
                                        //     std::collections::hash_map::Entry::Vacant(e) => {},
                                        //     std::collections::hash_map::Entry::Occupied(mut e) => {
                                        //         *e.get_mut() = fn_summary.covered;
                                        //     }
                                        // }

                                        // if let std::collections::hash_map::Entry::Vacant(e) = covered.entry(mod_func.clone()) {
                                        //     if fn_summary.covered > 0 {
                                        //         // This means that the current test reached a function that wasn't covered before
                                        //         e.insert(fn_summary.covered);
                                        //     } else if fn_summary.covered > *covered.get(&mod_func).unwrap() {
                                        //         *covered.get_mut(&mod_func).unwrap() = fn_summary.covered;
                                        //     }
                                        // }
                                    }

                                }

                            }
                            else {

                                // Let's check if this test generated any new coverage
                                println!("{:#?} passed", &test_path.0);

                                let compiled_modules = &cov_info.compiled_modules;
                                let mut new_cov: bool = false;

                                for i in &cov_info.module_maps {
                                    let module_summary = summarize_inst_cov_by_module(
                                        compiled_modules.get(&i.0.0).unwrap(),
                                        Some(&i.1),
                                    );

                                    for (fn_name, fn_summary) in module_summary.function_summaries.iter() {
                                        let mod_func = module_summary.module_name.name().as_str().to_string() + &fn_name.to_string();
                                        if covered.contains_key(&mod_func) {
                                            // Check if we have more coverage for the function
                                            if fn_summary.covered > *covered.get(&mod_func).unwrap() {
                                                new_cov = true;
                                                *covered.get_mut(&mod_func).unwrap() = fn_summary.covered;
                                            }

                                        } else if fn_summary.covered > 0 {
                                            // This means that the current test reached a function that wasn't covered before
                                            new_cov = true;
                                            covered.insert(mod_func, fn_summary.covered);
                                        }

                                        // if let std::collections::hash_map::Entry::Vacant(e) = covered.entry(mod_func.clone()) {
                                        //     if fn_summary.covered > 0 {
                                        //         // This means that the current test reached a function that wasn't covered before
                                        //         new_cov = true;
                                        //         // covered.insert(mod_func, fn_summary.covered);
                                        //         e.insert(fn_summary.covered);
                                        //     } else if fn_summary.covered > *covered.get(&mod_func).unwrap() {
                                        //         new_cov = true;
                                        //         *covered.get_mut(&mod_func).unwrap() = fn_summary.covered;
                                        //     }
                                        // }

                                    }

                                }

                                // //Because the test generated new coverage, mutate it and add a new version to our queue
                                // let new_test = format!("test{}", count);
                                // count += 1;
                                //
                                // // Copy the calls in the old test to the new test
                                // fs::copy(&test_path.0, &new_test).expect("Could not create new test from old test");
                                //
                                // let file = OpenOptions::new().write(true).append(true).open(&new_test).unwrap();
                                //
                                // // Add a new function call to the new test
                                // // a) Randomly select which function to add
                                // let idx = between.sample(&mut rng);
                                // // b) Write a function call for the randomly selected function to the new test
                                // fuzz_inputs(&template[idx], &file).expect("could not write to new test");
                                //
                                // // Push the new test to the queue
                                // pq.push(new_test, test_path.1 + 1);

                                // Push the old (seed) test back to the queue, with the correct adjusted priority
                                match clone {
                                    Some(test) => {
                                        if new_cov {
                                            println!("{:#?} gave new coverage", test.0);
                                            println!("{:#?} mutated into test {}", test.0, count);

                                            //Because the test generated new coverage, mutate it and add a new version to our queue
                                            let new_test = format!("test{}", count);
                                            count += 1;

                                            // Copy the calls in the old test to the new test
                                            fs::copy(&test_path.0, &new_test).expect("Could not create new test from old test");

                                            let file = OpenOptions::new().write(true).append(true).open(&new_test).unwrap();

                                            // Add a new function call to the new test
                                            // a) Randomly select which function to add
                                            let idx = between.sample(&mut rng);
                                            // b) Write a function call for the randomly selected function to the new test
                                            // fuzz_inputs(&template[idx], &file).expect("could not write to new test");
                                            let generate_new = coinflip::flip();
                                            if generate_new {
                                                let new_signer = get_signer();
                                                fuzz_inputs(&template[idx], &file, new_signer.clone()).expect("could not write to new test");
                                                signers.push(new_signer);
                                            } else {
                                                fuzz_inputs(&template[idx], &file, signers[0].clone()).expect("could not write to new test");
                                            }
                                            // Push the new test to the queue
                                            pq.push(new_test, test_path.1 + 1);
                                            pq.push(test.0.to_string(), test.1);
                                        } else {
                                            pq.push(test.0.to_string(), test.1 - 1);
                                        }

                                    }
                                    None => {}
                                }


                                // move this old test to the "ran" folder
                                // move_tests(&test_path, "RAN".to_string());
                            }
                            println!("{} test(s) ran.", test_passed);


                        }
                        Err(ex) => eprintln!("Test {:#?} failed with error: {}", &test_path.0, ex),
                    }
                    // If module coverage is 100%, break
                    let mut all_covered = true;
                    for (_, module_summary) in cov_info.clone().into_module_summaries() {
                        // module_summary.summarize_human(&mut summary_writer, true)?;
                        // println!()
                        for (fn_name, fn_summary) in module_summary.function_summaries.iter() {
                            if !fn_summary.fn_is_native {
                                let cov_per: f64 = fn_summary.percent_coverage();
                                if cov_per != 100_f64 {
                                    all_covered = false
                                }
                                println!("fun {} \t\t% coverage: {:.2}", fn_name, fn_summary.percent_coverage());
                            }
                        }
                    }
                    println!("\n");
                    if all_covered { break; }
                }
            },
            None => println!("No test found."),
        }
    }

    // Begin cleanup by moving the created tests into their respective folders
    for i in &pq {
        let exp_name = i.0.clone().to_owned() + ".exp";
        // If this test was ran, it would have an .exp with its name
        let tested = Path::new(&exp_name).exists();
        // Move the tests that didn't give an error either to the tested or not-tested directories
        if tested {
            move_tests(&i.0, "RAN".to_string()).
                expect("Failed to move test to the tested folder");
        } else {
            move_tests(&i.0, "NOT_RAN".to_string()).
                expect("Failed to move test to the tested folder");
        }
    }

    // if any test fails, bail
    let test_failed = test_total.checked_sub(test_passed).unwrap();
    if test_failed != 0 {
        anyhow::bail!("{} / {} test(s) failed.", test_failed, test_total)
    }

    // show coverage information if requested
    let mut summary_writer: Box<dyn Write> = Box::new(io::stdout());
    for (_, module_summary) in cov_info.into_module_summaries() {
        module_summary.summarize_human(&mut summary_writer, true)?;
    }
    println!("deque is {:#?}", pq);

    Ok(())
}

//module summary has the function names, lines covered out of total lines
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{sandbox::utils::module, DEFAULT_BUILD_DIR, DEFAULT_STORAGE_DIR, sandbox};
use move_command_line_common::{env::read_bool_env_var, files::{path_to_string},
                               testing::{format_diff, EXP_EXT}};
use move_compiler::command_line::COLOR_MODE_ENV_VAR;
use move_coverage::summary::{summarize_inst_cov_by_module};
use move_coverage::coverage_map::{CoverageMap, ExecCoverageMapWithModules};
use move_package::{
    compilation::{compiled_package::OnDiskCompiledPackage, package_layout::CompiledPackageLayout},
    source_package::{layout::SourcePackageLayout, manifest_parser::parse_move_manifest_from_file}};
use std::{collections::{BTreeMap, HashMap}, env, fs::{self, File, OpenOptions},
          io::{self, BufRead, Write}, path::{Path, PathBuf}, process::Command, };
use std::collections::HashSet;
use std::fs::read_dir;
use sandbox::commands::test::{copy_deps, simple_copy_dir};
use coinflip;
use tempfile::tempdir;
use move_binary_format::internals::ModuleIndex;
use move_binary_format::file_format::SignatureToken::{
    Bool, Signer, U128, U8, U64, Address, Vector, Reference};
use move_core_types::account_address::AccountAddress;
use rand::distributions::{Distribution};
use priority_queue::PriorityQueue;
use move_binary_format::file_format::SignatureToken;
use rand::{Rng};
use queue_file::QueueFile;
use move_binary_format::CompiledModule;
use move_binary_format::file_format::FunctionDefinition;

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
/// dump the execution trace to. The trace will be used by the coverage tool.
const DEFAULT_TRACE_FILE: &str = "trace";

const BACKUP_QUEUE: &str = "backup_queue.qf";
const TEMP_QUEUE: &str = "temp_queue.qf";

const FUZZ_TEST_DIR: &str = "fuzz-tests/";
const PASSED_DIR: &str = "tested-passed/";
const ERROR_DIR: &str = "tested-error/";
const NOT_TESTED_DIR: &str = "not-tested/";
const NEW_COV_DIR: &str = "new-coverage/";
const NO_NEW_COV_DIR: &str = "no-new-coverage/";

#[derive(PartialEq, Clone)]
enum FuzzPath {Fuzz, Passed, Err, PassedNoNewCov, PassedNewCov, ErrNoNewCov, ErrNewCov, NotTested}
impl FuzzPath {
    fn get_path(&self) -> String {
        match self {
            FuzzPath::Fuzz => FUZZ_TEST_DIR.to_owned(),
            FuzzPath::Passed => FUZZ_TEST_DIR.to_owned() + PASSED_DIR,
            FuzzPath::Err => FUZZ_TEST_DIR.to_owned() + ERROR_DIR,
            FuzzPath::PassedNoNewCov => FUZZ_TEST_DIR.to_owned() + PASSED_DIR + NO_NEW_COV_DIR,
            FuzzPath::PassedNewCov => FUZZ_TEST_DIR.to_owned() + PASSED_DIR + NEW_COV_DIR,
            FuzzPath::ErrNoNewCov => FUZZ_TEST_DIR.to_owned() + ERROR_DIR + NO_NEW_COV_DIR,
            FuzzPath::ErrNewCov => FUZZ_TEST_DIR.to_owned() + ERROR_DIR + NEW_COV_DIR,
            FuzzPath::NotTested => FUZZ_TEST_DIR.to_owned() + NOT_TESTED_DIR,
        }
    }
}


struct TestTemplate {
    mod_addr: AccountAddress,
    mod_name: String,
    func_name: String,
    params: Vec<SignatureToken>,
    type_args: bool, // TODO: MAKE THIS AN INT
}

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
    // let mut exe_dir = args_path.parent().unwrap();
    // TODO: MAKE THIS PROPER
    let exe_dir = Path::new(".");
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
            Some(path) => env::set_var(MOVE_VM_TRACING_ENV_VAR_NAME,
                                       path.as_os_str()),
        }

        let cmd_output = cli_command_template().args(args_iter).output()?;

        //TODO:
        // output += &format!("Command `{}`:\n", args_line);
        // let _ = write_fmt(output, "Command `{}`:\n", args_line);
        output += &*"Command `{".to_string();
        output += &*args_line;
        output += "`:\n";
        output += std::str::from_utf8(&cmd_output.stdout)?;
        output += std::str::from_utf8(&cmd_output.stderr)?;

        // Check to see if any of the commands ran generated any errors
        // TODO
        if std::str::from_utf8(&cmd_output.stdout)?.contains(&"error") ||
            std::str::from_utf8(&cmd_output.stdout)?.contains(&"aborted") ||
            std::str::from_utf8(&cmd_output.stdout)?.contains(&"failed") ||
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
                fs::write(file_path, "").expect("failed to write coverage");
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
        if let Some(trace_path) = &trace_file {
            if trace_path.exists() {
                fs::remove_file(trace_path)?;
            }
        }
    }

    // release the temporary workspace explicitly
    if let Some((t, _)) = temp_dir {
        t.close()?;
    }

    // compare output and exp_file
    let update_baseline = true;
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

fn get_test(info: &CompiledModule, f_def: &FunctionDefinition) -> TestTemplate {
    // Obtain the function name from the coverage map
    let func = &info.function_handles[f_def.function.into_index()];
    let name_idx = func.name.into_index();
    let func_name: String = info.identifiers[name_idx].as_str().to_owned();
    let mut type_args = false;
    if !&func.type_parameters.is_empty() {
        println!("{:#?} takes type args", &func_name);
        type_args = true; //TODO:
    }

    // Obtain the function signature from the coverage map
    let param_idx = func.parameters.into_index();
    let parameters = &info.signatures[param_idx].0;

    let mod_idx = func.module.into_index();
    let id_idx = info.module_handles[mod_idx].name.into_index();
    let module: String = info.identifiers[id_idx].as_str().to_owned();

    let addr_idx = info.module_handles[mod_idx].address.into_index();
    let mod_addr = info.address_identifiers[addr_idx];

    TestTemplate { mod_addr, mod_name: module, func_name, params: parameters.to_vec(),
        type_args }
}

fn start_fuzz(
    exe_dir: &Path, cli_binary: &Path, use_temp_dir: bool, test_name: &str, resume: bool,
    is_dpn: &bool, init_file: Option<&str>, init_func: Option<&str>,
) -> Result<(Vec<TestTemplate>, Vec<String>, ExecCoverageMapWithModules, u64, Vec<TestTemplate>),
    anyhow::Error> {
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

    // Disable colors in error reporting from the Move compiler
    env::set_var(COLOR_MODE_ENV_VAR, "NONE");

    cli_command_template().arg("package").arg("build").output()?;
    cli_command_template().arg("sandbox").arg("publish").output()?;

    let mut tests: Vec<TestTemplate> = Vec::new();
    let mut init_test: Vec<TestTemplate> = Vec::new();
    let mut type_arg_pool: Vec<String> = Vec::new();

    match &trace_file {
        None => None,
        Some(trace_path) => {
            let file_path = PathBuf::from(trace_path);
            fs::write(file_path, "").expect("couldn't write coverage to trace file");

            let canonical_build = &build_output.canonicalize().unwrap();
            let package_name = parse_move_manifest_from_file(
                &SourcePackageLayout::try_find_root(&canonical_build).unwrap(),
            )?.package.name.to_string();

            let pkg = OnDiskCompiledPackage::from_path(
                &build_output
                    .join(package_name)
                    .join(CompiledPackageLayout::BuildInfo.path()),
            )?
                .into_compiled_package()?;

            let src_modules = pkg
                .all_modules()
                .map(|unit| {
                    let absolute_path =
                        path_to_string(&unit.source_path.canonicalize()?)?;
                    Ok((absolute_path, module(&unit.unit)?.clone()))
                })
                .collect::<anyhow::Result<HashMap<_, _>>>()?;

            for (entry, info) in &src_modules {
                // TODO: concat /

                // Create a pool of structures to pass as type_args when fuzzing
                if !entry.contains("dependencies") {
                    for struct_def in &info.struct_defs {
                        // Get the name of the structure
                        let struct_handle_idx = struct_def.struct_handle.into_index();
                        let struct_name_idx =
                            info.struct_handles[struct_handle_idx].name.into_index();
                        let struct_name =
                            &info.identifiers[struct_name_idx].as_str().to_owned();

                        // Get the name and address of the module that declares the structure
                        let struct_mod_idx =
                            info.struct_handles[struct_handle_idx].module.into_index();
                        let mod_name_idx =
                            info.module_handles[struct_mod_idx].name.into_index();
                        let mod_addr_idx =
                            info.module_handles[struct_mod_idx].address.into_index();
                        let mod_name = &info.identifiers[mod_name_idx].as_str().to_owned();
                        let mod_addr =
                            &info.address_identifiers[mod_addr_idx].to_hex_literal();

                        let final_struct = mod_addr.to_owned() + "::" + mod_name + "::" +
                            struct_name;
                        // For now, for simplicity, only structures that don't take type
                        // arguments are being used
                        if info.struct_handles[struct_handle_idx].type_parameters.is_empty() {
                            type_arg_pool.push(final_struct)
                        }
                    }
                }

                if entry.ends_with(test_name) {
                    // Import the modules to be fuzzed in the test script
                    for f_def in &info.function_defs {
                        if f_def.is_entry {
                            tests.push(get_test(&info, f_def))
                        }
                    }
                }
                if *is_dpn && entry.ends_with(&init_file.unwrap()) {
                    for f_def in &info.function_defs {
                        if f_def.is_entry {
                            // Obtain the function name from the coverage map
                            let func =
                                &info.function_handles[f_def.function.into_index()];
                            let name_idx = func.name.into_index();
                            let func_name: String = info.identifiers[name_idx].as_str().to_owned();
                            if func_name == init_func.unwrap() {
                                init_test.push(get_test(&info, f_def));
                            }
                        }
                    }
                }
            }
            Some(trace_path)
        }
    };

    let mut cov_info = ExecCoverageMapWithModules::empty();
    let mut prev_count = 0;
    let tests_ran_folders = [
        FuzzPath::ErrNewCov.get_path(), FuzzPath::ErrNoNewCov.get_path(),
        FuzzPath::PassedNewCov.get_path(), FuzzPath::PassedNoNewCov.get_path(),
        FuzzPath::NotTested.get_path()
    ];

    for path in tests_ran_folders {
        if Path::new(&path).exists() && resume {
            let paths = read_dir(&path).unwrap();
            let num_tests: u64 = paths.count().try_into().unwrap();
            prev_count += num_tests / 2;
        }
    }

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

    // If we are resuming the fuzzer, re-run the tests that gave new coverage (whether they passed
    // or gave an error), to obtain the coverage info again

    let dirs = vec![
        FuzzPath::PassedNewCov.get_path(),
        FuzzPath::ErrNewCov.get_path(),
    ];
    if resume {
        for p in dirs {
            if Path::new(&p).exists() {
                for entry in read_dir(p)? {
                    let file = entry.unwrap();
                    let path = "./".to_owned() +
                        &file.path().as_path().display().to_string();
                    if !path.contains(".exp") {
                        println!("RE-RUNNING: {:#?}", path);
                        match run_one(&PathBuf::from(&path), cli_binary, use_temp_dir)
                        {
                            Ok(tuple) => {
                                if let Some(cov) = tuple.0 {
                                    cov_info.merge(cov);
                                }
                            }
                            Err(ex) => eprintln!("Test {:#?} failed with error: {}",
                                                 &path, ex),
                        }
                    }
                }
            }
        }
    }

    Ok((tests, type_arg_pool, cov_info, prev_count, init_test))
}

// Creates a signer by randomly 32 selecting valid hex digits
pub fn get_signer() -> String {
    // One hex = 2^4 = 4 bits = 1/2 byte
    // Two hex = 2^8 = 8 bits = 1 byte
    let address_bits = vec![
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F",
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
    let special_nums_u8: Vec<u8> = vec![0, 1, u8::MAX - 1, u8::MAX];
    let special_nums_u64: Vec<u64> = vec![0, 1, u64::MAX - 1, u64::MAX];
    let special_nums_u128: Vec<u128> = vec![0, 1, u128::MAX - 1, u128::MAX];

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
        let rand_num = rng.gen_range(2..u8::MAX - 1);
        rand_num.to_string()
    } else if int_type == &U64 {
        let rand_num = rng.gen_range(2..u64::MAX - 1);
        rand_num.to_string()
    } else {
        let rand_num = rng.gen_range(2..u128::MAX - 1);
        rand_num.to_string()
    }
}

fn fuzz_inputs(
    f: &TestTemplate,
    mut output: &File,
    module_signers: &[String],
    is_dpn: &bool,
    type_arg_pool: &[String],
) -> anyhow::Result<(bool, Vec<String>)> {
    let mut t: String = "sandbox run storage/0x".to_owned() +
        &f.mod_addr.to_string() +
        "/modules/" + &f.mod_name.to_string() + ".mv ";

    let mut signer_count = 0;
    let mut args_pres = false;
    let mut args = Vec::new();
    let mut new_signers_and_addrs = Vec::new();
    let mut added_new = false;

    let mut rng = rand::thread_rng();

    for (_i, p) in f.params.iter().enumerate() {
        if p == &Reference(Box::new(Signer)) || *p == Signer {
            signer_count += 1;
        } else {
            args_pres = true;
            if p == &U8 || p == &U64 || p == &U128 {
                args.push(fuzz_int(p))
            } else if p == &Bool {
                args.push(coinflip::flip().to_string())
            } else if *p == Address || p == &Address {
                // All the addresses we use are from our existing pool of signers
                let generate_new = false;
                // TODO
                // = coinflip::flip();
                if generate_new || module_signers.is_empty() {
                    // Generate a new signer (address)
                    let new_signer = get_signer();
                    args.push(new_signer.clone());
                    new_signers_and_addrs.push(new_signer.clone());
                    added_new = true;
                } else {
                    // Reuse an old signer
                    let between =
                        rand::distributions::Uniform::from(0..module_signers.len());
                    let idx = between.sample(&mut rng);
                    args.push(module_signers[idx].clone());
                }
                // For now, just using hard-coded addresses
            } else if *p == Vector(Box::new(U8)) {
                let generate_new = coinflip::flip();
                if generate_new {
                    args.push("x\"00000000000000000000000000000000\"".parse()?)
                } else {
                    args.push("b\"DD\"".parse()?)
                }
            }
        }
    }

    t += &f.func_name;
    t += " ";

    // TODO
    // Write a type-arg if the function takes type-args
    if *is_dpn && f.type_args {
        let between = rand::distributions::Uniform::from(0..type_arg_pool.len());
        let idx = between.sample(&mut rng);
        t += "--type-args ";
        t += &type_arg_pool[idx];
        t += " ";
    }

    if signer_count > 0 {
        t += "--signers ";
        for _n in 0..signer_count {
            let mut new_signer = get_signer();
            let generate_new = false;
            // TODO: coinflip::flip();
            if generate_new || module_signers.is_empty() {
                new_signers_and_addrs.push(new_signer.clone());
                added_new = true;
            } else {
                let between =
                    rand::distributions::Uniform::from(0..module_signers.len());
                let idx = between.sample(&mut rng);
                new_signer = module_signers[idx].clone()
            }
            t += &(new_signer + " ");
        }
    }

    if args_pres {
        t += "--args ";
        for a in args {
            t += &(a.to_owned() + " ");
        }
    }
    t += "-v ";

    writeln!(output, "{}", t).expect("Failed to write to args file");
    Ok((added_new, new_signers_and_addrs))
}

fn move_tests(test_path: &String, folder_type: FuzzPath) -> Result<String, anyhow::Error> {
    let splits: Vec<&str> = test_path.split('/').collect();
    let file_name = splits.last().unwrap().to_string();
    let test_name = folder_type.clone().get_path() + &*file_name;

    // Create a file in the error folder to copy the test to
    File::create(&test_name)?;

    // Copy the test and corresponding exp file to the tests-error directory
    fs::copy(&test_path, &test_name)?;

    // Delete the original test and exp file
    fs::remove_file(&test_path)?;

    if folder_type != FuzzPath::NotTested {
        // In these cases, there is also a .exp file we need to get rid of for the test
        let exp_name = test_name.to_owned() + ".exp";
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

pub fn setup_fuzz_dirs() -> anyhow::Result<()> {
    // Create a directory to store the output tests of our fuzzer

    let paths = [
        FuzzPath::Fuzz.get_path(),
        FuzzPath::Passed.get_path(),
        FuzzPath::Err.get_path(),
        FuzzPath::PassedNoNewCov.get_path(),
        FuzzPath::PassedNewCov.get_path(),
        FuzzPath::ErrNewCov.get_path(),
        FuzzPath::ErrNoNewCov.get_path(),
        FuzzPath::NotTested.get_path()
    ];

    for p in paths {
        let path = Path::new(&p);
        fs::create_dir(path).expect("Failed to create fuzz tests directory");
        if let Some(pa) = path.parent() { fs::create_dir_all(pa)? };
    }

    Ok(())
}

pub fn fuzzer(
    args_path: &Path, cli_binary: &Path, use_temp_dir: bool,
    // This is the name of the file whose functions are to be tested
    test_name: &str, is_dpn: &bool, init_file: Option<&str>, init_func: Option<&str>, resume: &bool,
) -> anyhow::Result<()> {
    let mut test_total: u64 = 0;
    let mut test_passed: u64 = 0;

    // This queue holds the names of the test files. Tests will be popped from this queue, ran,
    // and if they receive positive feedback, then a mutated version will be pushed to the back
    // of the queue. Once ran, all tests will be moved to the "used" test directory under the
    // fuzz-tests folder that is generated when running the fuzz cli command.
    let mut pq = PriorityQueue::new();

    // Returns an array of function templates (module name, function name,
    // parameters and module address)
    let init_info =
        start_fuzz(args_path, cli_binary, use_temp_dir, test_name, *resume,
                   is_dpn, init_file, init_func).unwrap();
    let template = init_info.0;
    let type_arg_pool = init_info.1;
    let mut cov_info = init_info.2;

    // This will be used to keep track of the number of tests created
    let mut count = 0;
    if *resume {
        count = init_info.3 + 1;
        println!("COVERAGE RESUMED AT:");
        for (_, module_summary) in cov_info.clone().into_module_summaries() {
            for (fn_name, fn_summary) in
            module_summary.function_summaries.iter() {
                if !fn_summary.fn_is_native {
                    println!("fun {} \t\t% coverage: {:.2}", fn_name,
                             fn_summary.percent_coverage());
                }
            }
        }
        println!("\n");
    }

    let mut last_count = 0;
    if count > 0 {
        last_count = count - 1;
    }
    let last_test = "test".to_owned() + &last_count.to_string();
    let mut last_test_found = false;
    let mut latest_test = 0;

    if *resume {
        let mut queue_file = BACKUP_QUEUE;
        if !Path::new(queue_file).is_file() {
            queue_file = TEMP_QUEUE;
        }

        let mut qf = QueueFile::open(queue_file)
            .expect("cannot open queue file");

        let mut seed: String = "".to_owned();

        for (index, elem) in qf.iter().enumerate() {
            if index % 2 == 0 {
                seed = std::str::from_utf8(&elem).unwrap_or("<invalid>").to_owned();
            } else {
                let priority: u64 = (std::str::from_utf8(&elem).unwrap_or("<invalid>"))
                    .parse::<u64>().expect("not a number").to_owned();

                // If the last test was created, check to see if it was also added to the queue
                if seed == last_test {
                    last_test_found = true;
                }

                let test_num = &seed[4..seed.len()].to_string();
                let test_num_as_int = test_num.parse().unwrap();
                if test_num_as_int > latest_test {
                    latest_test = test_num_as_int
                }

                // If the latest test ran before pausing gave an error, but wasn't removed from the
                // queue yet, don't add it to the queue we are rebuilding
                let test_new_cov =
                    &(FuzzPath::ErrNewCov.get_path() + &seed.clone());
                let test_no_new_cov =
                    &(FuzzPath::ErrNoNewCov.get_path() + &seed.clone());

                let is_error = Path::new(test_new_cov).is_file() ||
                    Path::new(test_no_new_cov).is_file();

                if !is_error {
                    pq.push(seed.clone(), priority);
                } else {
                    println!("NOT ADDING {:#?}", &seed);
                    if test_name.contains(&("test".to_owned() + &count.to_string())) {
                        count += 1;
                    }
                }
            }
        }
        println!("RESTORED PRIORITY QUEUE IS: {:#?}", pq);
    }


    // If a test was created and ran (because it's trace exists), but not added to our queue,
    // push it back to our queue with the top priority, so it can be rerun
    if *resume && !last_test_found {
        println!("we may need to remove {:#?}", last_test);
        if Path::new(&last_test).is_file() {
            println!("removed {:#?}", last_test);
            fs::remove_file(&last_test)?;
            // decrement count
            count -= 1;
        } else if !(Path::new(&(FuzzPath::ErrNewCov.get_path() + &last_test)).is_file()
            || Path::new(&(FuzzPath::ErrNoNewCov.get_path() + &last_test)).is_file()
        ) {
            // decrement count
            count -= 1;
        }
    }

    if latest_test >= count && *resume {
        count = latest_test + 1
    }
    println!("count is {:#?}", count);

    if !*resume {
        setup_fuzz_dirs().expect("Could not set-up test directories");
    }

    // This will keep track of any signers used so far, starting with a few default signers
    let mut signers: Vec<String> = vec!["0xA550C18".to_string(), "0xB1E55ED".to_string(),
                                        "0xDD".to_string(), "0xA".to_string(), "0xb".to_string()];

    // For each of the eligible functions in the library, push an initial test for it to the queue
    if !*resume {
        for func in template.iter() {
            let new_test = format!("test{}", count);
            let mut output = File::create(FuzzPath::NotTested.get_path()
                + &new_test)?;

            // First line in each test should be "sandbox publish", with different flags depending
            // on if it's run through the Move cli, or the Diem cli.
            if *is_dpn {
                writeln!(output, "sandbox publish --bundle --with-deps")
                    .expect("Failed to write to args file");

                // For df-cli (targeting the DPN), write the set-up command to the test file
                let init_func_info = &init_info.4[0];
                fuzz_inputs(init_func_info, &output, &signers, is_dpn,
                            &type_arg_pool).unwrap();
            } else {
                writeln!(output, "sandbox publish").expect("Failed to write to args file");
            }

            // This will write some tests into our testfile
            let mut fuzz_output =
                fuzz_inputs(func, &output, &signers, is_dpn, &type_arg_pool)
                    .unwrap();
            // Add any new signers or addresses to our store
            if fuzz_output.0 {
                signers.append(&mut fuzz_output.1)
            }
            // Add the test to our queue
            pq.push(new_test, 100);
            count += 1;
        }
    }

    // Random number generator to choose which function
    let between = rand::distributions::Uniform::from(0..template.len());
    let mut rng = rand::thread_rng();

    let mut covered: HashMap<String, u64> = HashMap::new();
    let mut tests_ran: HashSet<String> = HashSet::new();

    let compiled_mods = &cov_info.compiled_modules;
    // If resuming, reset the covered hashmap, with functions and the number of lines reached
    // in each one
    if *resume {
        for i in &cov_info.module_maps {
            let module_summary = summarize_inst_cov_by_module(
                compiled_mods.get(&i.0.0).unwrap(),
                Some(i.1),
            );

            for (fn_name, fn_summary) in
            module_summary.function_summaries.iter() {
                let mod_func = module_summary.module_name.name().as_str().to_string()
                    + &fn_name.to_string();

                match covered.entry(mod_func.clone()) {
                    std::collections::hash_map::Entry::Vacant(e) => {
                        if fn_summary.covered > 0 {
                            // This means that the current test reached a function that wasn't
                            // covered before
                            e.insert(fn_summary.covered);
                        }
                    }
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        // Check if we have more coverage for the function
                        if fn_summary.covered > *e.get() {
                            *e.get_mut() = fn_summary.covered;
                        }
                    }
                }
            }
        }

        // Then, also add any tests already ran in the tests_ran hash set
        let tested_paths = [
            &FuzzPath::PassedNoNewCov.get_path(),
            &FuzzPath::PassedNewCov.get_path()
        ];
        for path in tested_paths {
            if Path::new(path).exists() {
                for entry in read_dir(&path)? {
                    let file = entry?;
                    let file_path = file.path().into_os_string().into_string().unwrap();
                    let splits: Vec<&str> = file_path.split('/').collect();
                    let file_name = splits.last().unwrap().to_string();

                    let len = file_name.chars().count();
                    let ending = &file_name[len - 3..len];

                    if ending != "exp" {
                        tests_ran.insert(file_name);
                    }
                }
            }
        }
    }
    println!("TESTS RAN {:#?}", tests_ran);

    // For now, it will fuzz until no tests are left in the queue
    // User must manually stop the program otherwise
    while true {
        if pq.is_empty() {

            for func in template.iter() {
                let new_test = format!("test{}", count);
                let mut output_file =
                    File::create(FuzzPath::NotTested.get_path() + &new_test)?;

                // First line in each test should be "sandbox publish"
                if *is_dpn {
                    writeln!(output_file, "sandbox publish --bundle --with-deps")
                        .expect("Failed to write to args file");

                    let init_func_info = &init_info.4[0];
                    fuzz_inputs(init_func_info, &output_file, &signers,
                                is_dpn, &type_arg_pool).unwrap();
                } else {
                    writeln!(output_file, "sandbox publish").
                        expect("Failed to write to args file");
                }

                // This will write some tests into our testfile
                let mut output =
                    fuzz_inputs(func, &output_file, &signers, is_dpn,
                                &type_arg_pool).unwrap();
                // Add any new signers or addresses to our store
                if output.0 {
                    signers.append(&mut output.1)
                }
                // Add the test to our queue
                pq.push(new_test, 100);
                count += 1;
            }
        }

        let seed = pq.pop();
        let clone = seed.clone();
        match seed {
            Some(test_path) => {
                if tests_ran.contains(&test_path.0) {
                    println!("{:#?} mutated now into test {}", &test_path.0, count);

                    // Regardless if the test generated new coverage, mutate it and add a new 
                    // version to our queue
                    let new_test = format!("test{}", count);
                    count += 1;

                    // Copy the calls in the old test to the new test
                    // Old test could either be in the new-coverage folder, or the tested folder
                    let mut old_test_path = FuzzPath::PassedNoNewCov.get_path() +
                        &test_path.0;
                    if !Path::new(&old_test_path).is_file() {
                        old_test_path = FuzzPath::PassedNewCov.get_path() + &test_path.0;
                    }
                    let new_test_path = FuzzPath::NotTested.get_path() + &new_test;

                    fs::copy(&old_test_path, &new_test_path)
                        .expect("Could not create new test from old test");

                    let file = OpenOptions::new().write(true).append(true)
                        .open(&new_test_path).unwrap();

                    // Add a new function call to the new test
                    // a) Randomly select which function to add
                    let idx = between.sample(&mut rng);

                    // b) Write a function call for the randomly selected function to the new test
                    let mut output =
                        fuzz_inputs(&template[idx], &file, &signers,
                                    is_dpn, &type_arg_pool)
                            .unwrap();
                    // Add any new signers or addresses to our store
                    if output.0 {
                        signers.append(&mut output.1)
                    }

                    // Push the new test to the queue
                    pq.push(new_test, test_path.1 + 1);
                    // Push the old test to the queue
                    pq.push(test_path.0.to_string(), test_path.1 - 1);
                } else {
                    match run_one(
                        Path::new(&(FuzzPath::NotTested.get_path() + &test_path.0)),
                        cli_binary, use_temp_dir) {
                        Ok(tuple) => {
                            tests_ran.insert(test_path.clone().0);

                            test_total = test_total.checked_add(1).unwrap();
                            test_passed = test_passed.checked_add(1).unwrap();

                            if let Some(cov) = tuple.0 {
                                cov_info.merge(cov);
                            }

                            let is_error = tuple.1;
                            if is_error {
                                // Remove this test from our queue
                                println!("{:#?} gave an error", &test_path.0);

                                let compiled_modules =
                                    &cov_info.compiled_modules;

                                let mut new_cov = false;

                                for i in &cov_info.module_maps {
                                    let module_summary =
                                        summarize_inst_cov_by_module(
                                            compiled_modules.get(&i.0.0).unwrap(),
                                            Some(i.1),
                                        );

                                    for (fn_name, fn_summary) in
                                    module_summary.function_summaries.iter() {
                                        let mod_func = module_summary.module_name.name()
                                            .as_str().to_string() + &fn_name.to_string();

                                        match covered.entry(mod_func.clone()) {
                                            std::collections::hash_map::Entry::
                                            Vacant(e) => {
                                                if fn_summary.covered > 0 {
                                                    // This means that the current test reached a
                                                    // function that wasn't covered before
                                                    println!("{:#?} had an error, but reached this \
                                                    function for the first time: {:#?}",
                                                             &test_path.0, &mod_func);
                                                    e.insert(fn_summary.covered);
                                                    new_cov = true;
                                                }
                                            }
                                            std::collections::hash_map::Entry::
                                            Occupied(mut e) => {
                                                // Check if we have more coverage for the function
                                                if fn_summary.covered > *e.get() {
                                                    println!("{:#?} had an error, but gave new \
                                                    coverage in function: {:#?}",
                                                             &test_path.0, &mod_func);
                                                    *e.get_mut() = fn_summary.covered;
                                                    new_cov = true;
                                                }
                                            }
                                        }
                                    }
                                }

                                let old_test_path = FuzzPath::NotTested.get_path() +
                                    &test_path.0;
                                if new_cov {
                                    //move this test to the new-coverage error folder
                                    move_tests(&old_test_path,
                                               FuzzPath::ErrNewCov).
                                        expect("Failed to move test to the error folder");
                                } else {
                                    //move this test to the no new-coverage error folder
                                    move_tests(&old_test_path,
                                               FuzzPath::ErrNoNewCov).
                                        expect("Failed to move test to the error folder");
                                }
                            } else {

                                // Let's check if this test generated any new coverage
                                println!("{:#?} passed", &test_path.0);

                                let compiled_modules =
                                    &cov_info.compiled_modules;
                                let mut new_cov: bool = false;

                                for i in &cov_info.module_maps {
                                    let module_summary =
                                        summarize_inst_cov_by_module
                                            (compiled_modules.get(&i.0.0).unwrap(),
                                             Some(i.1));

                                    for (fn_name, fn_summary) in
                                    module_summary.function_summaries.iter() {
                                        let mod_func = module_summary.module_name.name().
                                            as_str().to_string() + &fn_name.to_string();

                                        match covered.entry(mod_func.clone()) {
                                            std::collections::hash_map::Entry::
                                            Vacant(e) => {
                                                if fn_summary.covered > 0 {
                                                    // This means that the current test reached a
                                                    // function that wasn't covered before
                                                    e.insert(fn_summary.covered);
                                                    new_cov = true;
                                                }
                                            }
                                            std::collections::hash_map::Entry::
                                            Occupied(mut e) => {
                                                // Check if we have more coverage for the function
                                                if fn_summary.covered > *e.get() {
                                                    *e.get_mut() = fn_summary.covered;
                                                    new_cov = true;
                                                }
                                            }
                                        }
                                    }
                                }

                                // Push the old (seed) test back to the queue, with the correctly
                                // adjusted priority
                                match clone {
                                    Some(test) => {
                                        let old_test_path =
                                            FuzzPath::NotTested.get_path() + &test_path.0;
                                        if new_cov {
                                            println!("{:#?} gave new coverage", test.0);
                                            println!("{:#?} mutated into test {}", test.0, count);

                                            //Because the test generated new coverage, mutate it
                                            // and add a new version to our queue
                                            let new_test = format!("test{}", count);
                                            count += 1;

                                            // Copy the calls in the old test to the new test
                                            let new_test_path =
                                                FuzzPath::NotTested.get_path() + &new_test;

                                            fs::copy(&old_test_path, &new_test_path).
                                                expect("Could not create new test from \
                                                old test");

                                            let file = OpenOptions::new().write(true).
                                                append(true).open(&new_test_path).unwrap();

                                            // Add a new function call to the new test
                                            // a) Randomly select which function to add
                                            let idx = between.sample(&mut rng);

                                            // b) Write a function call for the randomly selected
                                            // function to the new test
                                            let mut output =
                                                fuzz_inputs(&template[idx], &file,
                                                            &signers, is_dpn,
                                                            &type_arg_pool).unwrap();
                                            // Add any new signers or addresses to our store
                                            if output.0 {
                                                signers.append(&mut output.1)
                                            }
                                            // Push the new test to the queue
                                            pq.push(new_test, test_path.1 + 1);
                                            pq.push(test.0.to_string(), test.1);
                                            // Move the test to the tested directory
                                            move_tests(&old_test_path,
                                                       FuzzPath::PassedNewCov).
                                                expect("Failed to move test to the new-\
                                                coverage tested folder");
                                        } else {
                                            pq.push(test.0.to_string(), test.1 - 5);
                                            // Move the test to the tested directory
                                            move_tests(&old_test_path,
                                                       FuzzPath::PassedNoNewCov).
                                                expect("Failed to move test to the no new-\
                                                coverage tested folder");
                                        }
                                    }
                                    None => {}
                                }
                            }
                            println!("{} test(s) ran.", test_passed);
                        }
                        Err(ex) => eprintln!("Test {:#?} failed with error: {}",
                                             &test_path.0, ex),
                    }
                    // If module coverage is 100%, break
                    let mut all_covered = true;
                    for (_, module_summary) in
                    cov_info.clone().into_module_summaries() {
                        for (fn_name, fn_summary) in
                        module_summary.function_summaries.iter() {
                            if !fn_summary.fn_is_native {
                                let cov_per: f64 = fn_summary.percent_coverage();
                                if cov_per != 100_f64 {
                                    all_covered = false
                                }
                                println!("fun {} \t\t% coverage: {:.2}", fn_name,
                                         fn_summary.percent_coverage());
                            }
                        }
                    }
                    println!("\n");
                    if all_covered { break; }
                }
            }
            None => println!("No test found."),
        }

        // Backup our queue, in case of pause and resume
        let mut new_qf = QueueFile::open(TEMP_QUEUE)
            .expect("cannot open queue file");

        // For each test (seed) in the priority queue, write both the test name,
        // followed by its priority to the queue-file
        for i in pq.iter() {
            new_qf.add(i.0.as_bytes()).expect("add failed");
            new_qf.add(i.1.to_string().as_bytes()).expect("add failed");
        }

        // We can now delete the outdated backup queue
        if Path::new(BACKUP_QUEUE).exists() {
            fs::remove_file(BACKUP_QUEUE)?;
        }

        // Rename the temp queue to the proper name to indicate that it contains a complete
        // version of the priority queue
        fs::rename(TEMP_QUEUE, BACKUP_QUEUE).expect("Failed to rename temp queue");
    }

    // if any test fails, bail
    let test_failed = test_total.checked_sub(test_passed).unwrap();
    if test_failed != 0 {
        anyhow::bail!("{} / {} test(s) failed.", test_failed, test_total)
    }

    // show coverage information
    let mut summary_writer: Box<dyn Write> = Box::new(io::stdout());
    for (_, module_summary) in cov_info.into_module_summaries() {
        module_summary.summarize_human(&mut summary_writer, true)?;
    }

    Ok(())
}



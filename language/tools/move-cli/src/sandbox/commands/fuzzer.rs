// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::VecDeque;
use crate::{sandbox::utils::module, DEFAULT_BUILD_DIR, DEFAULT_STORAGE_DIR};

use move_command_line_common::{
    env::read_bool_env_var,
    files::{find_filenames, path_to_string},
    testing::{format_diff, read_env_update_baseline, EXP_EXT},
};
use move_compiler::command_line::COLOR_MODE_ENV_VAR;
use move_coverage::coverage_map::{CoverageMap, ExecCoverageMapWithModules};
use move_package::{
    compilation::{compiled_package::OnDiskCompiledPackage, package_layout::CompiledPackageLayout},
    resolution::resolution_graph::ResolvedGraph,
    source_package::{layout::SourcePackageLayout, manifest_parser::parse_move_manifest_from_file},
    BuildConfig,
};
use std::{
    collections::{BTreeMap, HashMap},
    env,
    fs::{self, File},
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::tempdir;
use move_binary_format::internals::ModuleIndex;
use move_binary_format::file_format::SignatureToken::Signer;
use move_binary_format::file_format::SignatureToken::Reference;
use move_binary_format::file_format::SignatureToken::U64;
use move_binary_format::file_format::Visibility::Script;
use move_core_types::account_address::AccountAddress;
use move_binary_format::CompiledModule;
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

pub fn fuzz_func(
    mod_addr: AccountAddress,
    module: String,
    func_name: String, 
    parameters: Vec<move_binary_format::file_format::SignatureToken>
) -> String {
    println!("function is: {} {} {}", func_name, module, mod_addr);
    let mut t : String = "sandbox run storage/0x".to_owned() + 
                        &mod_addr.to_string() + 
                        "/modules/" + &module.to_string() +  
                        &".mv ".to_owned();

    let mut signer_pres = false;
    let mut args_pres = false;
    let mut args = Vec::new();
    let mut module_signer = "0x1234abcd";

    for (i, p) in parameters.iter().enumerate() {
        if p == &Reference(Box::new(Signer)) {
            signer_pres = true;
        } else {
            args_pres = true;
            if p == &U64 {
                args.push("12345678");
            }
        }
    }

    if signer_pres {
        t += &("--signers ".to_owned() + &module_signer.to_string() + &" ".to_owned());
    }
    if args_pres {
        t += "--args ";
        for a in args {
            t += &(a.to_owned() + &" ".to_owned());
        }
    }
    t += "-v ";
    t += &func_name;
    return t;
}


fn print_type_of<T>(_: &T) -> &str {
    println!("{}", std::any::type_name::<T>());
    return std::any::type_name::<T>();
}

fn collect_coverage(
    args_path: &Path,
    // TODO: we don't need to run it once to get the compiled modules,
    // those modules are available from the OnDiskCompiledPackage
    trace_file: &Path,
    build_dir: &Path,
    mo: &String
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
    write!(output, "{:#?}", coverage_map);   

    Ok(coverage_map)
}

fn determine_package_nest_depth(
    resolution_graph: &ResolvedGraph,
    pkg_dir: &Path,
) -> anyhow::Result<usize> {
    let mut depth = 0;
    for (_, dep) in resolution_graph.package_table.iter() {
        depth = std::cmp::max(
            depth,
            dep.package_path.strip_prefix(pkg_dir)?.components().count() + 1,
        );
    }
    Ok(depth)
}

fn pad_tmp_path(tmp_dir: &Path, pad_amount: usize) -> anyhow::Result<PathBuf> {
    let mut tmp_dir = tmp_dir.to_path_buf();
    for i in 0..pad_amount {
        tmp_dir.push(format!("{}", i));
    }
    std::fs::create_dir_all(&tmp_dir)?;
    Ok(tmp_dir)
}

// We need to copy dependencies over (transitively) and at the same time keep the paths valid in
// the package. To do this we compute the resolution graph for all possible dependencies (so in dev
// mode) and then calculate the nesting under `tmp_dir` the we need to copy the root package so
// that it, and all its dependencies reside under `tmp_dir` with the same paths as in the original
// package manifest.
fn copy_deps(tmp_dir: &Path, pkg_dir: &Path) -> anyhow::Result<PathBuf> {
    // Sometimes we run a test that isn't a package for metatests so if there isn't a package we
    // don't need to nest at all.
    let package_resolution = match (BuildConfig {
        dev_mode: true,
        ..Default::default()
    })
    .resolution_graph_for_package(pkg_dir)
    {
        Ok(pkg) => pkg,
        Err(_) => return Ok(tmp_dir.to_path_buf()),
    };
    let package_nest_depth = determine_package_nest_depth(&package_resolution, pkg_dir)?;
    let tmp_dir = pad_tmp_path(tmp_dir, package_nest_depth)?;
    for (_, dep) in package_resolution.package_table.iter() {
        let source_dep_path = &dep.package_path;
        let dest_dep_path = tmp_dir.join(&dep.package_path.strip_prefix(pkg_dir).unwrap());
        if !dest_dep_path.exists() {
            fs::create_dir_all(&dest_dep_path)?;
        }
        simple_copy_dir(&dest_dep_path, source_dep_path)?;
    }
    Ok(tmp_dir)
}

fn simple_copy_dir(dst: &Path, src: &Path) -> io::Result<()> {
    for entry in fs::read_dir(src)? {
        let src_entry = entry?;
        let src_entry_path = src_entry.path();
        let dst_entry_path = dst.join(src_entry.file_name());
        if src_entry_path.is_dir() {
            fs::create_dir_all(&dst_entry_path)?;
            simple_copy_dir(&dst_entry_path, &src_entry_path)?;
        } else {
            fs::copy(&src_entry_path, &dst_entry_path)?;
        }
    }
    Ok(())
}

/// Run the `args_path` batch file with`cli_binary`
pub fn run_one(
    args_path: &Path,
    cli_binary: &Path,
    use_temp_dir: bool,
    mo: &str,
) -> anyhow::Result<(Option<ExecCoverageMapWithModules>, bool)> {
    // (Option<ExecCoverageMapWithModules>, bool)
    // anyhow::Result<Option<(ExecCoverageMapWithModules, bool)>>
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
    let mut wks_dir = temp_dir.as_ref().map_or(exe_dir, |t| &t.1);
   
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
        println!("cmd output is {:#?}", &cmd_output);
        
        // Check to see if any of the commands ran generated any errors
        if std::str::from_utf8(&cmd_output.stdout)?.contains(&"error") {
            error_present = true;
        } else if std::str::from_utf8(&cmd_output.stderr)? != "" {
            error_present = true;
        }
    }

    println!("erorr present is {:#?}", error_present );


    // collect coverage information
    let cov_info = match &trace_file {
        None => None,
        Some(trace_path) => {
            if trace_path.exists() {
                Some(collect_coverage(args_path, trace_path, &build_output, &mo.to_string() )?)
            } else {
                let file_path = PathBuf::from(trace_path);
                std::fs::write(file_path, "");
                Some(collect_coverage(args_path, trace_path, &build_output, &mo.to_string() )?)
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
                // fs::remove_file(trace_path)?;
            }
        }
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
    mo: &str,
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
    let mut output = "".to_string();

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

    let cov_info = match &trace_file {
        None => None,
        Some(trace_path) => {
            let file_path = PathBuf::from(trace_path);
            std::fs::write(file_path, "");

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
                if !entry.contains("dependencies") {        
                    // Import the modules to be fuzzed in the test script
                    for f_def in &info.function_defs {
                        if f_def.visibility == Script {
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

                            let mut test = TestTemplate {
                                mod_addr: mod_addr,
                                mod_name: module,
                                func_name: func_name, 
                                params: parameters.to_vec()
                            };
                            tests.push(test)
                        }
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
    // // OK(&src_modules)
   
}

pub fn fuzz_inputs(
    f: &TestTemplate,
    c: u64
) -> Result<String, anyhow::Error> {

    let path = format!("test{}", c);
    let mut output = File::create(&path)?;

    // writeln!(output, "{}", "package build").expect("Failed to write to args file");
    writeln!(output, "{}", "sandbox publish").expect("Failed to write to args file");
   let mut t : String = "sandbox run storage/0x".to_owned() + 
                        &f.mod_addr.to_string() + 
                        "/modules/" + &f.mod_name.to_string() +  
                        &".mv ".to_owned();

    let mut signer_pres = false;
    let mut args_pres = false;
    let mut args = Vec::new();
    let mut module_signer = "0x1234abcd";

    for (i, p) in f.params.iter().enumerate() {
        if p == &Reference(Box::new(Signer)) {
            signer_pres = true;
        } else {
            args_pres = true;
            if p == &U64 {
                args.push("12345678");
            }
        }
    }

    if signer_pres {
        t += &("--signers ".to_owned() + &module_signer.to_string() + &" ".to_owned());
    }
    if args_pres {
        t += "--args ";
        for a in args {
            t += &(a.to_owned() + &" ".to_owned());
        }
    }
    t += "-v ";
    t += &f.func_name;

    writeln!(output, "{}", t).expect("Failed to write to args file");
    return Ok(path);

}

pub fn move_tests(test_path: &String, folder_type: String) -> Result<String, anyhow::Error> {
    let mut folder = "tests-error/";
    if (folder_type == "RAN") {
        folder = "tests-ran/";
    }

    let mut test_name = "fuzz-tests/".to_owned() + &folder.to_owned() + &test_path.to_owned();
    let mut exp_name = "fuzz-tests/".to_owned() + &folder.to_owned() + &test_path.to_owned() + &".exp".to_owned();
    let exp_path = test_path.to_owned() + &".exp".to_owned();
    
    // Create a file in the error folder to copy the test to
    File::create(&test_name)?;
    File::create(&exp_name)?;

    // Copy the test and corresponding exp file to the tests-error directory
    fs::copy(&test_path, &test_name)?;
    fs::copy(&exp_path, &exp_name)?;

    // Delete the orginal test and exp file
    fs::remove_file(&test_path)?;
    fs::remove_file(&exp_path)?;

    return Ok(exp_path);
}

pub fn fuzzer(
    args_path: &Path,
    cli_binary: &Path,
    use_temp_dir: bool,
    // This is the name of the module to be tested
    mo: &String
) -> anyhow::Result<()> {
    let mut test_total: u64 = 0;
    let mut test_passed: u64 = 0;
    let mut cov_info = ExecCoverageMapWithModules::empty();


    // Create a directory to store the output tests of our fuzzer
    let fuzz_path = Path::new("fuzz-tests");
    fs::create_dir(fuzz_path);
    if let Some(p) = fuzz_path.parent() { fs::create_dir_all(p)? };

    // Create a subdirectory for tests that invoke errors in the target program
    let error_path = Path::new("fuzz-tests/tests-error");
    fs::create_dir(error_path);
    if let Some(p) = error_path.parent() { fs::create_dir_all(p)? };

    // Create a subdirectory for tests that have been run
    let ran_path = Path::new("fuzz-tests/tests-ran");
    fs::create_dir(ran_path);
    if let Some(p) = ran_path.parent() { fs::create_dir_all(p)? };
   
    // Returns an array of function templates (module name, function name, parameters and module address)
    let template = start_fuzz(args_path, cli_binary, use_temp_dir, mo).unwrap();
    let mut count = 0;
    let mut test_paths: Vec<String> = Vec::new();

    // For each of the eligible functions in the library, push an initial test for it to test_paths, 
    // from which we will form our queue
    for func in template.iter() {
        let path = fuzz_inputs(&func, count).unwrap();
        test_paths.push(path);
        count = count + 1;
    }

    // This queue holds the names of the test files. Tests will be popped from this queue, ran, 
    // and if they receive positive feedback, then a mutated version will be pushed to the back 
    // of the queue. Once ran, all tests will be moved to the "used" test directory under the fuzz-tests
    // folder that is generated when running the fuzz cli command.
    let mut deque = VecDeque::from(test_paths);

    while deque.len() != 0 {
        match deque.pop_front() {
            Some(test_path)   => {
                match run_one(Path::new(&("./".to_owned() + &test_path)), cli_binary, use_temp_dir, mo) {
                    Ok(tuple) => {
                        test_passed = test_passed.checked_add(1).unwrap();
  
                        if let Some(cov) = tuple.0 {
                            cov_info.merge(cov);
                        }

                        let is_error = tuple.1;
                        if is_error {
                            //move this test to the error folder
                            move_tests(&test_path, "ERROR".to_string());
                        } else {
                            // mutate test and push new version to the queue


                            // move this old test to the "ran" folder
                            move_tests(&test_path, "RAN".to_string());
                        }

                    }
                    Err(ex) => eprintln!("Test {} failed with error: {}", test_path, ex),
                }
                test_total = test_total.checked_add(1).unwrap();
                println!("{} / {} test(s) passed.", test_passed, test_total);
            },
            None => println!("No test found."),
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

    Ok(())
}

//module summary has the function names, lines covered out of total lines
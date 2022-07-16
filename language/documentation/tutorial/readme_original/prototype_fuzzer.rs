use std::process::{Command, ExitStatus, Stdio};
use std::collections::HashMap;
// use std::io::BufReader;
use std::io::Result;
use std::env;
use std::fs;
// use std::fs::File;

// Execute terminal command functions from within this rust program
pub fn execute(exe: &str, args: &[&str]) -> Result<ExitStatus> {
    Command::new(exe).args(args).spawn()?.wait()
}

// To execute, run ./fuzzer <path to package directory> <module name>
// For now, only testing one module at a time
fn main() {
    // Retrieve any command line arguements passed in by the user
    let args: Vec<String> = env::args().collect();

    // To begin the fuxzzing process, first build and publish the package
    execute("move", &["package", "build"]).expect("Failed to build package");
    execute("move", &["sandbox", "publish", "-v"]).expect("Failed to publish package to sandbox");

    // Next dissemble the module and collect information about all functions and their arguments
    let output = Command::new("move")
        .args(["package", "disassemble", "--name", &args[2]])
        .stdout(Stdio::piped())
        .output()
        .expect("Failed to disassemble module");

    // Write the disassemble output to a file
    let file_name: String = "disassemble".to_owned() + &args[2];
    let stdout = String::from_utf8(output.stdout).unwrap();
    fs::write(file_name, &stdout)
        .expect("Failed to write to file");

    // let file = File::open(file_name);
    // io::BufReader::new(file).lines();

    // let mut scores = HashMap::new();
    let mut module_functions: HashMap<String, Vec<(String, String)>> = HashMap::new();
    module_functions.insert("Blue".to_string(), vec![("COOL".to_string(), "cal".to_string()), ("BAD".to_string(), "sal".to_string())]);
    // scores.insert(String::from("Blue"), [10, 20, 30]);
    // scores.insert(String::from("Yellow"), [50, 5, 40]);

    // for (key, value) in &scores {
    //     println!("{}: {}", key, value);
    // }
    // println!("{:?}", scores.get("Blue"));
    for (key, value) in &module_functions {
        println!("{} {:?}", key, value[1].1);
    }
    
    // Find functions and store them and their arguments in an array

    // Generate script with tests

    // Generate arg file to call running of scripts

    // Gnearte expected results and track coverage
    env::set_var("UPDATE_BASELINE", "1");
    // args[1] holds the module name
    execute("move",  &["sandbox", "exp-test", "-p", &args[1], "--track-cov"])
        .expect("Failed to test module and track coverage");
}

// to clean state: move sandbox clean
// republish: move sandbox publish  

// order in which functions are called matters for coverage, must try different orders and sequences
// figure out how to call script with nultple command line args

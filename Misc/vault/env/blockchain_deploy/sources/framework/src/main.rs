use std::env;
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::mem::drop;
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use move_transactional_test_runner::{
    framework::{MaybeNamedCompiledModule, MoveTestAdapter},
    tasks::TaskInput,
};
use move_bytecode_source_map::{source_map::SourceMap, utils::source_map_from_file};
use move_binary_format::file_format::CompiledModule;
use move_symbol_pool::Symbol;
use move_core_types::{
    u256::U256,
    account_address::AccountAddress, 
    language_storage::TypeTag,
    runtime_value::MoveValue
};

use sui_types::base_types::SuiAddress;
use sui_ctf_framework::NumericalAddress;
use sui_transactional_test_runner::{
    args::{SuiValue, ViewObjectCommand, SuiSubcommand},
    test_adapter::{FakeID, SuiTestAdapter},
};


macro_rules! handle_err {
    ($stream:expr, $msg:expr, $err:expr) => {{
        let full = format!("[SERVER ERROR] {}: {}", $msg, $err);
        eprintln!("{}", full);
        let _ = $stream.write_all(full.as_bytes());   // ignore write failures
        drop($stream);                                // close socket
        return Err::<(), Box<dyn std::error::Error>>(full.into());
    }};
}
/// helper function used to display an object with given `FakeID`
async fn view_object(
    adapter: &mut SuiTestAdapter, 
    id: FakeID
) -> Result<String, Box<dyn Error>> {
    let arg_view = TaskInput {
        command: SuiSubcommand::ViewObject(ViewObjectCommand { id }),
        name: "view-object".to_string(),
        number: 5,
        start_line: 1,
        command_lines_stop: 1,
        stop_line: 1,
        data: None,
        task_text: "".to_string(),
    };

    match adapter.handle_subcommand(arg_view).await {
        Ok(out) => Ok(out.unwrap()),
        Err(error) => Err(error.into()),
    }
}

async fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {

    // initialize SuiTestAdapter
    let modules = vec!["vault", "vault_coin"];
    let mut deployed_modules: Vec<AccountAddress> = Vec::new();

    let named_addresses = vec![
        (
            "challenge".to_string(),
            NumericalAddress::parse_str(
                "0x0", 
            )?,
        ),
        (
            "solution".to_string(),
            NumericalAddress::parse_str(
                "0x0",
            )?,
        ),
        (
            "admin".to_string(),
            NumericalAddress::parse_str(
                "0xfccc9a421bbb13c1a66a1aa98f0ad75029ede94857779c6915b44f94068b921e",
            )?,
        ),
    ];

    let mut adapter = sui_ctf_framework::initialize(
        named_addresses,
        Some(vec![
            "challenger".to_string(),
            "solver".to_string()
        ]),
    ).await;

    let mut mncp_modules : Vec<MaybeNamedCompiledModule> = Vec::new();

    for i in 0..modules.len() {

        let module = &modules[i];

        let mod_path = format!("./chall/build/challenge/bytecode_modules/{}.mv", module);
        let src_path = format!("./chall/build/challenge/source_maps/{}.mvsm", module);
        let mod_bytes: Vec<u8> = std::fs::read(mod_path)?;

        let module: CompiledModule = match CompiledModule::deserialize_with_defaults(&mod_bytes) {
            Ok(data) => data,
            Err(e) => {
                let _ = adapter.cleanup_resources().await;
                println!("[SERVER] error: {e}");
                return Err("error during deserialization".into())
            }
        }; 
        let named_addr_opt: Option<Symbol> = Some(Symbol::from("challenge"));
        let source_map: Option<SourceMap> = match source_map_from_file(Path::new(&src_path)) {
            Ok(data) => Some(data),
            Err(e) => {
                let _ = adapter.cleanup_resources().await;
                println!("[SERVER] error: {e}");
                return Err("error during generating source map".into())
            }
        };

        let maybe_ncm = MaybeNamedCompiledModule {
            named_address: named_addr_opt,
            module,
            source_map,
        };

        mncp_modules.push( maybe_ncm );
    }

    // publish challenge module
    let chall_dependencies: Vec<String> = Vec::new();
    let chall_addr = match sui_ctf_framework::publish_compiled_module(
        &mut adapter,
        mncp_modules,
        chall_dependencies,
        Some(String::from("challenger")),
    ).await {
        Some(addr) => addr,
        None => {
            stream.write_all("[SERVER] Error publishing module".as_bytes()).unwrap();
            let _ = adapter.cleanup_resources().await;
            return Ok(());
        }
    };

    deployed_modules.push(chall_addr);
    println!("[SERVER] Module published at: {:?}", chall_addr); 

    // get the solution bytes
    stream.write_all("[SERVER] solution:".as_bytes()).unwrap();
    let mut solution_data = [0_u8; 2000];
    let _ = stream.read(&mut solution_data)?;

    // send challenge address
    let mut output = String::new();
    fmt::write(
        &mut output,
        format_args!(
            "[SERVER] Challenge modules published at: {}",
            chall_addr.to_string().as_str(),
        ),
    )
    .unwrap();
    stream.write_all(output.as_bytes()).unwrap();

    // publish solution module
    let sol_dependencies: Vec<String> = vec![ String::from("challenge") ];

    let mut mncp_solution : Vec<MaybeNamedCompiledModule> = Vec::new();
    let module: CompiledModule = match CompiledModule::deserialize_with_defaults(solution_data.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            let _ = adapter.cleanup_resources().await;
            println!("[SERVER] error: {e}");
            return Err("error during deserialization".into())
        }
    }; 
    let named_addr_opt: Option<Symbol> = Some(Symbol::from("solution"));
    let source_map : Option<SourceMap> = None;
    
    let maybe_ncm = MaybeNamedCompiledModule {
        named_address: named_addr_opt,
        module,
        source_map,
    }; 
    mncp_solution.push( maybe_ncm );

    let sol_addr = match sui_ctf_framework::publish_compiled_module(
        &mut adapter,
        mncp_solution,
        sol_dependencies,
        Some(String::from("solver")),
    ).await {
        Some(addr) => addr,
        None => {
            stream.write_all("[SERVER] Error publishing module".as_bytes()).unwrap();
            // close tcp socket
            drop(stream);
            let _ = adapter.cleanup_resources().await;
            return Ok(());
        }
    };
    println!("[SERVER] Solution published at: {:?}", sol_addr);

    // send solution address
    output = String::new();
    fmt::write(
        &mut output,
        format_args!(
            "[SERVER] Solution published at {}",
            sol_addr.to_string().as_str()
        ),
    )
    .unwrap();
    stream.write_all(output.as_bytes()).unwrap();

    
    let mut args_sol: Vec<SuiValue> = Vec::new();
    let mut type_args_sol : Vec<TypeTag> = Vec::new();
    args_sol.push(SuiValue::Object(FakeID::Enumerated(1, 2), None));
    args_sol.push(SuiValue::Object(FakeID::Enumerated(1, 1), None));
    args_sol.push(SuiValue::Object(FakeID::Enumerated(1, 5), None));
    
    // Call solve Function
    let ret_val = match sui_ctf_framework::call_function(
        &mut adapter,
        sol_addr,
        "solution",
        "solve",
        args_sol,
        type_args_sol,
        Some("solver".to_string()),
    ).await {
        Ok(output) => output,
        Err(e) => handle_err!(stream, "Calling solve failed", e),
    };
    println!("[SERVER] Return value {:#?}", ret_val);
    println!("");

    // Check Solution
    let mut args2: Vec<SuiValue> = Vec::new();
    args2.push(SuiValue::Object(FakeID::Enumerated(3, 0), None));

    let type_args_valid : Vec<TypeTag> = Vec::new();

    // Validate Solution
    let _sol_ret = match  sui_ctf_framework::call_function(
        &mut adapter,
        chall_addr,
        "vault",
        "has_flag",
        args2,
        type_args_valid,
        Some("solver".to_string()),
    ).await {
        Ok(_output) => {
            println!("[SERVER] Correct Solution!");
            println!("");
            if let Ok(flag) = env::var("FLAG") {
                let message = format!("[SERVER] Congrats, flag: {}", flag);
                stream.write(message.as_bytes()).unwrap();
            } else {
                stream.write("[SERVER] Flag not found, please contact admin".as_bytes()).unwrap();
            }
        }
        Err(e) => handle_err!(stream, "Calling has_flag failed", e),
    };
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // create socket - port 31337
    let listener = TcpListener::bind("0.0.0.0:31337")?;
    println!("[SERVER] Starting server at port 31337!");

    let local = tokio::task::LocalSet::new();

    // wait for incoming solution
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("[SERVER] New connection: {}", stream.peer_addr()?);
                    let result = local.run_until( async move {
                        tokio::task::spawn_local( async {
                            handle_client(stream).await
                        }).await
                    }).await;
                    println!("[SERVER] Result: {:?}", result);
            }
            Err(e) => {
                println!("[SERVER] Error: {}", e);
            }
        }
    }

    // close socket server
    drop(listener);
    Ok(())
}

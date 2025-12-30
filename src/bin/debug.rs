use std::env;
use tree_sitter::Parser;

fn main() {
    let mut parser = Parser::new();

    let language = tree_sitter_bash::LANGUAGE;
    match parser.set_language(&language.into()) {
        Ok(_) => {}
        Err(e) => {
            println!("Failed to set language: {}", e);
            return;
        }
    }

    let cmd = env::args().skip(1).collect::<Vec<_>>().join(" ");
    if cmd.is_empty() {
        println!("Usage: debug <command>");
        return;
    }

    println!("Parsing: {}", cmd);
    match parser.parse(&cmd, None) {
        Some(tree) => {
            let root = tree.root_node();
            println!("S-expr:\n{}", root.to_sexp());
        }
        None => println!("Failed to parse"),
    }
}

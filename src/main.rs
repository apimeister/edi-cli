use std::{fmt::Display, process};

use clap::{arg, Command};
use regex::Regex;

fn main() {
    let matches = Command::new("edi")
        .version("1.0")
        .about("Edi file processing")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("edi2json")
                .about("Transforms an EDI into a Json document")
                .arg(arg!([FILENAME]).required(true)),
        )
        .subcommand(
            Command::new("json2edi")
                .about("Transforms an Json into a EDI document")
                .arg(arg!([FILENAME]).required(true)),
        )
        .subcommand(
            Command::new("encoding")
                .about("returns either 'X12' or 'EDIFACT' if encoding can be determined, otherwise 'UNKNOWN'.")
                .arg(arg!([FILENAME]).required(true)),
        )
        .subcommand(
            Command::new("type")
                .about("returns the X12 or EDIFACT message type")
                .arg(arg!([FILENAME]).required(true)),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encoding", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("FILENAME").unwrap();
            let str = std::fs::read_to_string(file_name).unwrap();
            let result = get_encoding(&str);
            println!("{result}");
        },
        Some(("type", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("FILENAME").unwrap();
            let str = std::fs::read_to_string(file_name).unwrap();
            let result = get_encoding(&str);
            match result {
                Encoding::Unknown => {
                    eprintln!("Cannot convert file, unknown encoding.");
                    process::exit(1);
                }
                Encoding::Edifact => {
                    let result = get_edifact_type(&str).unwrap();
                    println!("{}/{}", result.0, result.1);
                }
                Encoding::X12 => {
                    let result = get_x12_type(&str).unwrap();
                    println!("{}/{}", result.0, result.1);
                }
            }
        },
        Some(("edi2json", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("FILENAME").unwrap();
            let str = std::fs::read_to_string(file_name).unwrap();
            let result = get_encoding(&str);
            match result {
                Encoding::Unknown => {
                    eprintln!("Cannot convert file, unknown encoding.");
                    process::exit(1);
                }
                Encoding::Edifact => {
                    let result = get_edifact_type(&str).unwrap();
                    eprintln!("Edifact type not support. please open an issue under https://github.com/apimeister/edi-cli/ for type {}/{}",result.0,result.1);
                    process::exit(1);
                }
                Encoding::X12 => {
                    let result = get_x12_type(&str).unwrap();
                    if result.1 == "310" {
                        let edi: x12_types::v004010::_310 = serde_x12::from_str(&str).unwrap();
                        println!("{:?}",edi);
                        return;
                    }
                    if result.1 == "315" {
                        let edi: x12_types::v004010::Transmission<x12_types::v004010::_315> = serde_x12::from_str(&str).unwrap();
                        let json_str = serde_json::to_string(&edi).unwrap();
                        println!("{json_str}");
                        return;
                    }
                    eprintln!("X12 type not support. please open an issue under https://github.com/apimeister/edi-cli/ for type {}/{}",result.0,result.1);
                    process::exit(1);
                }
            }
        },
        _ => unimplemented!("Exhausted list of subcommands"),
    }
}

#[derive(PartialEq, Eq, Debug)]
enum Encoding {
    X12,
    Edifact,
    Unknown,
}

impl Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Encoding::X12 => write!(f, "X12"),
            Encoding::Edifact => write!(f, "EDIFACT"),
            Encoding::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

fn get_encoding(str: &str) -> Encoding {
    if str.starts_with("ISA") {
        Encoding::X12
    } else if str.starts_with("UNB") {
        Encoding::Edifact
    } else {
        Encoding::Unknown
    }
}

fn get_x12_type(str: &str) -> Result<(String, String), String> {
    //version
    let re = Regex::new(r#"(GS.*)\~"#).unwrap();
    let line = re.captures(str).unwrap();
    let line2 = line.get(0).unwrap().as_str().to_string();
    let line3 = line2.trim_end_matches('~').to_string();
    let parts: Vec<&str> = line3.split('*').collect();
    let version = parts.get(8).unwrap();
    //doctype
    let re = Regex::new(r#"(ST.*)\~"#).unwrap();
    let line = re.captures(str).unwrap();
    let line2 = line.get(0).unwrap().as_str().to_string();
    let line3 = line2.trim_end_matches('~').to_string();
    let parts: Vec<&str> = line3.split('*').collect();
    let doctype = parts.get(1).unwrap();
    Ok((version.to_string(), doctype.to_string()))
}

fn get_edifact_type(str: &str) -> Result<(String, String), String> {
    // UNH+2805567+IFTSTA:D:00B:UN'
    //version
    let re = Regex::new(r#"(UNH.*)'"#).unwrap();
    let line = re.captures(str).unwrap();
    let line2 = line.get(0).unwrap().as_str().to_string();
    let line3 = line2.trim_end_matches('\'').to_string();
    let parts: Vec<&str> = line3.split([':','+']).collect();
    let ver1 = parts.get(3).unwrap();
    let ver2 = parts.get(4).unwrap();
    let version = format!("{}{}", ver1, ver2);
    let doctype = parts.get(2).unwrap();
    Ok((version, doctype.to_string()))
}

#[test]
fn valid_x12_document() {
    let str = r#"ISA*00*          *00*          *ZZ*SOURCE         *02*TARGET         *220101*1449*U*00401*000011566*0*P*>~
GS*IO*SOURCE*TARGET*20220101*1449*61716*X*004010~"#;
    let result = get_encoding(str);
    assert_eq!(result, Encoding::X12);
}
#[test]
fn valid_edifact_document() {
    let str = r#"UNB+UNOC:2+SENDER:ZZZ+RECEIVER:ZZZ+220101:1021+2803570'
UNH+2805567+IFTSTA:D:00B:UN'"#;
    let result = get_encoding(str);
    assert_eq!(result, Encoding::Edifact);
}
#[test]
fn unknown_document1() {
    let str = "test123";
    let result = get_encoding(str);
    assert_eq!(result, Encoding::Unknown);
}
#[test]
fn unknown_document2() {
    let str = "";
    let result = get_encoding(str);
    assert_eq!(result, Encoding::Unknown);
}
#[test]
fn x12_type_extract() {
    let str = r#"GS*IO*SOURCE*TARGET*20220101*1449*61716*X*004010~
ST*310*35353~"#;
    let result = get_x12_type(str).unwrap();
    let version = result.0;
    let doctype = result.1;
    println!("{}/{}", version, doctype);
    assert_eq!(version, "004010");
    assert_eq!(doctype, "310");
}
#[test]
fn edifact_type_extract() {
    let str = r#"UNB+UNOC:2+SENDER:ZZZ+RECEIVER:ZZZ+220101:1021+2803570'
UNH+2805567+IFTSTA:D:00B:UN'
BGM+23+2BOG129382+9'
DTM+137:202201010021:203'"#;
    let result = get_edifact_type(str).unwrap();
    let version = result.0;
    let doctype = result.1;
    println!("{}/{}", version, doctype);
    assert_eq!(version, "D00B");
    assert_eq!(doctype, "IFTSTA");
}

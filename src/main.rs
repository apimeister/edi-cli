use clap::{arg, Command};
use encoding_rs::ISO_8859_16;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;
use std::{
    fmt::Display,
    fs::File,
    io::{BufReader, Read},
    process,
};
use x12_types::{util::Parser, *};

/// Generates the `(version, doctype)` dispatch table for both conversion
/// directions from a single source of truth.
///
/// Each entry maps an X12 envelope `(GS-08 version, ST-01 transaction set)`
/// pair to the matching `x12-types` module and document type, e.g.
/// `("005010", "850", v005010, _850)`.
macro_rules! x12_dispatch {
    ( $( ($ver:literal, $ty:literal, $module:ident, $doc:ident) ),* $(,)? ) => {
        /// Parse an X12 document of the given `(version, doctype)` into JSON.
        /// Returns `None` if the pair is not supported.
        fn x12_to_json(version: &str, doctype: &str, input: &str) -> Option<String> {
            let json = match (version, doctype) {
                $(
                    ($ver, $ty) => {
                        let (_rest, edi) =
                            $module::Transmission::<$module::$doc>::parse(input).unwrap();
                        serde_json::to_string(&edi).unwrap()
                    }
                )*
                _ => return None,
            };
            Some(json)
        }

        /// Render a JSON document of the given `(version, doctype)` back into X12.
        /// Returns `None` if the pair is not supported.
        fn json_to_x12(version: &str, doctype: &str, input: &str) -> Option<String> {
            let edi = match (version, doctype) {
                $(
                    ($ver, $ty) => {
                        let edi: $module::Transmission<$module::$doc> =
                            serde_json::from_str(input).unwrap();
                        format!("{edi}")
                    }
                )*
                _ => return None,
            };
            Some(edi)
        }
    };
}

x12_dispatch! {
    // v003030
    ("003030", "998", v003030, _998),

    // v004010
    ("004010", "204", v004010, _204),
    ("004010", "214", v004010, _214),
    ("004010", "301", v004010, _301),
    ("004010", "309", v004010, _309),
    ("004010", "310", v004010, _310),
    ("004010", "315", v004010, _315),
    ("004010", "322", v004010, _322),
    ("004010", "404", v004010, _404),
    ("004010", "810", v004010, _810),
    ("004010", "856", v004010, _856),
    ("004010", "940", v004010, _940),
    ("004010", "945", v004010, _945),
    ("004010", "997", v004010, _997),
    ("004010", "998", v004010, _998),

    // v005010
    ("005010", "148", v005010, _148),
    ("005010", "163", v005010, _163),
    ("005010", "180", v005010, _180),
    ("005010", "204", v005010, _204),
    ("005010", "210", v005010, _210),
    ("005010", "211", v005010, _211),
    ("005010", "212", v005010, _212),
    ("005010", "214", v005010, _214),
    ("005010", "216", v005010, _216),
    ("005010", "217", v005010, _217),
    ("005010", "270", v005010, _270),
    ("005010", "271", v005010, _271),
    ("005010", "274", v005010, _274),
    ("005010", "275", v005010, _275),
    ("005010", "276", v005010, _276),
    ("005010", "277", v005010, _277),
    ("005010", "278", v005010, _278),
    ("005010", "300", v005010, _300),
    ("005010", "301", v005010, _301),
    ("005010", "303", v005010, _303),
    ("005010", "304", v005010, _304),
    ("005010", "309", v005010, _309),
    ("005010", "310", v005010, _310),
    ("005010", "315", v005010, _315),
    ("005010", "350", v005010, _350),
    ("005010", "353", v005010, _353),
    ("005010", "404", v005010, _404),
    ("005010", "417", v005010, _417),
    ("005010", "425", v005010, _425),
    ("005010", "753", v005010, _753),
    ("005010", "754", v005010, _754),
    ("005010", "810", v005010, _810),
    ("005010", "811", v005010, _811),
    ("005010", "812", v005010, _812),
    ("005010", "816", v005010, _816),
    ("005010", "820", v005010, _820),
    ("005010", "821", v005010, _821),
    ("005010", "822", v005010, _822),
    ("005010", "823", v005010, _823),
    ("005010", "824", v005010, _824),
    ("005010", "830", v005010, _830),
    ("005010", "832", v005010, _832),
    ("005010", "834", v005010, _834),
    ("005010", "835", v005010, _835),
    ("005010", "837", v005010, _837),
    ("005010", "840", v005010, _840),
    ("005010", "843", v005010, _843),
    ("005010", "845", v005010, _845),
    ("005010", "846", v005010, _846),
    ("005010", "850", v005010, _850),
    ("005010", "852", v005010, _852),
    ("005010", "855", v005010, _855),
    ("005010", "856", v005010, _856),
    ("005010", "857", v005010, _857),
    ("005010", "860", v005010, _860),
    ("005010", "861", v005010, _861),
    ("005010", "862", v005010, _862),
    ("005010", "864", v005010, _864),
    ("005010", "865", v005010, _865),
    ("005010", "866", v005010, _866),
    ("005010", "867", v005010, _867),
    ("005010", "869", v005010, _869),
    ("005010", "870", v005010, _870),
    ("005010", "875", v005010, _875),
    ("005010", "880", v005010, _880),
    ("005010", "888", v005010, _888),
    ("005010", "889", v005010, _889),
    ("005010", "940", v005010, _940),
    ("005010", "943", v005010, _943),
    ("005010", "944", v005010, _944),
    ("005010", "945", v005010, _945),
    ("005010", "990", v005010, _990),
    ("005010", "997", v005010, _997),
    ("005010", "999", v005010, _999),

    // v005030
    ("005030", "404", v005030, _404),
}

fn main() {
    let matches = Command::new("edi")
        .version(std::env!("CARGO_PKG_VERSION"))
        .about("Edi file processing")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("edi2json")
                .about("Transforms an EDI into a Json document")
                .arg(arg!([FILENAME] "input file, - for <stdin>").required(true)),
        )
        .subcommand(
            Command::new("json2edi")
                .about("Transforms an Json into a EDI document")
                .arg(arg!([FILENAME] "input file, - for <stdin>").required(true)),
        )
        .subcommand(
            Command::new("encoding")
                .about("returns either 'X12' or 'EDIFACT' if encoding can be determined, otherwise 'UNKNOWN'.")
                .arg(arg!([FILENAME] "input file, - for <stdin>").required(true)),
        )
        .subcommand(
            Command::new("type")
                .about("returns the X12 or EDIFACT message type")
                .arg(arg!([FILENAME] "input file, - for <stdin>").required(true)),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encoding", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("FILENAME").unwrap();
            let str = read_file_with_unknown_encoding(file_name);
            let result = get_encoding(&str);
            println!("{result}");
        }
        Some(("type", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("FILENAME").unwrap();
            let str = read_file_with_unknown_encoding(file_name);
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
        }
        Some(("edi2json", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("FILENAME").unwrap();
            let str = read_file_with_unknown_encoding(file_name);
            let result = get_encoding(&str);
            match result {
                Encoding::Unknown => {
                    eprintln!("Cannot convert file, unknown encoding.");
                    process::exit(1);
                }
                Encoding::Edifact => {
                    let (version, _type) = get_edifact_type(&str).unwrap();
                    eprintln!("Edifact type not support. please open an issue under https://github.com/apimeister/edi-cli/ for type {version}/{_type}");
                    process::exit(1);
                }
                Encoding::X12 => {
                    let (version, _type) = get_x12_type(&str).unwrap();
                    match x12_to_json(&version, &_type, &str) {
                        Some(json_str) => println!("{json_str}"),
                        None => {
                            eprintln!("X12 type not support. please open an issue under https://github.com/apimeister/edi-cli/ for type {version}/{_type}");
                            process::exit(1);
                        }
                    }
                }
            }
        }
        Some(("json2edi", sub_matches)) => {
            let file_name = sub_matches.get_one::<String>("FILENAME").unwrap();
            let str = read_file_with_unknown_encoding(file_name);
            let val: Value = serde_json::from_str(&str).unwrap();
            // guess encoding
            let is_x12 = val.get("isa");
            if is_x12.is_some() {
                // X12 processing -> find type
                let fg = val.get("functional_group").unwrap();
                let fg1 = fg.as_array().unwrap().first().unwrap();
                let version = fg1.get("gs").unwrap().get("08").unwrap().as_str().unwrap();
                let segments = fg1.get("segments").unwrap();
                let segment1 = segments.as_array().unwrap().first().unwrap();
                let st = segment1.get("st").unwrap();
                let type_name = st.get("01").unwrap().as_str().unwrap();
                match json_to_x12(version, type_name, &str) {
                    Some(edi) => println!("{edi}"),
                    None => {
                        eprintln!("X12 type not support. please open an issue under https://github.com/apimeister/edi-cli/ for type {version}/{type_name}");
                        process::exit(1);
                    }
                }
            } else {
                // EDIFACT processing
                eprintln!("Edifact not yet supported.");
                process::exit(1);
            }
        }
        _ => unimplemented!("Exhausted list of subcommands"),
    }
}

fn read_file_with_unknown_encoding(file_name: &str) -> String {
    // check for stdin option
    if file_name == "-" {
        let mut buffer = String::new();
        let stdin = std::io::stdin();
        let lines = stdin.lines();
        for line in lines {
            let x = line.unwrap();
            buffer.push_str(&x);
        }
        buffer
    } else {
        let file = File::open(file_name).unwrap();
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).unwrap();
        // guess UT-8
        let result = String::from_utf8(buffer.clone());
        match result {
            Ok(str) => str,
            Err(_err) => {
                let (cow, _encoding_used, had_errors) = ISO_8859_16.decode(&buffer);
                if had_errors {
                    eprintln!("file is neither UTF-8 nor ISO8859-16, use ISO interpretation to go forward");
                }
                cow.to_string()
            }
        }
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
    } else if str.starts_with("UNB") || str.starts_with("UNA") {
        Encoding::Edifact
    } else {
        Encoding::Unknown
    }
}

fn get_x12_type(str: &str) -> Result<(String, String), String> {
    //version
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(GS.*)(~\n?ST)").unwrap();
    }
    let Some(line) = RE.captures(str) else {
        eprintln!("cannot read header line");
        process::exit(1);
    };
    let line2 = line.get(1).unwrap().as_str().to_string();
    let line3 = line2.trim_end_matches('~').to_string();
    let parts: Vec<&str> = line3.split('*').collect();
    let version = parts.get(8).unwrap();
    //doctype
    lazy_static! {
        static ref RE2: Regex = Regex::new(r"\~\n?(ST.*)\~").unwrap();
    }
    let line = RE2.captures(str).unwrap();
    let line2 = line.get(0).unwrap().as_str().to_string();
    let line3 = line2.trim_end_matches('~').to_string();
    let parts: Vec<&str> = line3.split('*').collect();
    let doctype = parts.get(1).unwrap();
    Ok((version.to_string(), doctype.to_string()))
}

fn get_edifact_type(str: &str) -> Result<(String, String), String> {
    // UNH+2805567+IFTSTA:D:00B:UN'
    //version
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"(UNH.*)'"#).unwrap();
    }
    let line = RE.captures(str).unwrap();
    let line2 = line.get(0).unwrap().as_str().to_string();
    let line3 = line2.trim_end_matches('\'').to_string();
    let parts: Vec<&str> = line3.split([':', '+']).collect();
    let ver1 = parts.get(3).unwrap();
    let ver2 = parts.get(4).unwrap();
    let version = format!("{ver1}{ver2}");
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
    println!("{version}/{doctype}");
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
    println!("{version}/{doctype}");
    assert_eq!(version, "D00B");
    assert_eq!(doctype, "IFTSTA");
}

#[test]
fn check_for_una() {
    let str = r#"UNA:+.? 'UNB+UNOC:3+SENDER+CRECEIVER+221121:1422+1291'UNH+"#;
    let result = get_encoding(str);
    println!("{result:?}");
    assert_eq!(result, Encoding::Edifact);
}

#[test]
fn check_for_unb() {
    let str = r#"UNB+UNOC:3+SNDR+RCVR+221121:1422+1291'UNH+"#;
    let result = get_encoding(str);
    println!("{result:?}");
    assert_eq!(result, Encoding::Edifact);
}

#[test]
fn check_edifact_cuscar() {
    let str = "UNB+UNOC:3+HKGHKG999+BLI-CUS+221121:0430+336'UNH+321+CUSCAR:D:96B:UN'BGM+85+CUSCAR/202211210430/+9'DTM+137:202211210430:203'RFF+AAZ:SUDU'NAD+MS+HSA'CTA+IC+:DAVID ZHANG/852-34788102'NAD+BA+HSA'TDT+20+246N+1+++++9178393:146:11:MERATUS MEDAN 5:ID'DTM+133:20221122:102'GIS+23'EQD+CN+MRKU7178024::ZZZ+22G1+++5'TSR++2:::2'MEA+AAE+T+KGM:2170'SEL+ML-ID0212928'EQD+CN+MSKU5705452::ZZZ+22G1+++5'TSR++2:::2'MEA+AAE+T+KGM:2180'SEL+ML-ID0212929'EQD+CN+GLDU5592412::ZZZ+22G1++";
    let result = get_edifact_type(str).unwrap();
    println!("{result:?}");
}

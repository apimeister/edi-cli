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
                    eprintln!("Edifact type not support. please open an issue under https://github.com/apimeister/edi-cli/ for type {}/{}",version,_type);
                    process::exit(1);
                }
                Encoding::X12 => {
                    let (version, _type) = get_x12_type(&str).unwrap();
                    let json_str = match (version.as_str(), _type.as_str()) {
                        ("003030", "998") => {
                            let (_rest, edi) =
                                v003030::Transmission::<v003030::_998>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        ("004010", "204") => {
                            let (_rest, edi) =
                                v004010::Transmission::<v004010::_204>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        // ("004010", "214") => {
                        //     let (_rest, edi) =
                        //         v004010::Transmission::<v004010::_214>::parse(&str).unwrap();
                        //     serde_json::to_string(&edi).unwrap()
                        // }
                        ("004010", "309") => {
                            let (_rest, edi) =
                                v004010::Transmission::<v004010::_309>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        ("004010", "310") => {
                            let (_rest, edi) =
                                v004010::Transmission::<v004010::_310>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        ("004010", "315") => {
                            let (_rest, edi) =
                                v004010::Transmission::<v004010::_315>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        // ("004010", "322") => {
                        //     let (_rest, edi) =
                        //         v004010::Transmission::<v004010::_322>::parse(&str).unwrap();
                        //     serde_json::to_string(&edi).unwrap()
                        // }
                        ("004010", "404") => {
                            let (_rest, edi) =
                                v004010::Transmission::<v004010::_404>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        // ("004010", "997") => {
                        //     let (_rest, edi) =
                        //         v004010::Transmission::<v004010::_997>::parse(&str).unwrap();
                        //     serde_json::to_string(&edi).unwrap()
                        // }
                        ("004010", "998") => {
                            let (_rest, edi) =
                                v004010::Transmission::<v004010::_998>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        ("005010", "834") => {
                            let (_rest, edi) =
                                v005010::Transmission::<v005010::_834>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        ("005010", "835") => {
                            let (_rest, edi) =
                                v005010::Transmission::<v005010::_835>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        ("005010", "837") => {
                            let (_rest, edi) =
                                v005010::Transmission::<v005010::_837>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        ("005030", "404") => {
                            let (_rest, edi) =
                                v005030::Transmission::<v005030::_404>::parse(&str).unwrap();
                            serde_json::to_string(&edi).unwrap()
                        }
                        _ => {
                            eprintln!("X12 type not support. please open an issue under https://github.com/apimeister/edi-cli/ for type {}/{}",version,_type);
                            process::exit(1);
                        }
                    };
                    println!("{json_str}");
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
                let fg1 = fg.as_array().unwrap().get(0).unwrap();
                let version = fg1.get("gs").unwrap().get("08").unwrap().as_str().unwrap();
                let segments = fg1.get("segments").unwrap();
                let segment1 = segments.as_array().unwrap().get(0).unwrap();
                let st = segment1.get("st").unwrap();
                let type_name = st.get("01").unwrap().as_str().unwrap();
                let edi = match (version, type_name) {
                    ("003030", "998") => {
                        let edi: v003030::Transmission<v003030::_998> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "204") => {
                        let edi: v004010::Transmission<v004010::_204> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "309") => {
                        let edi: v004010::Transmission<v004010::_309> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "310") => {
                        let edi: v004010::Transmission<v004010::_310> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "315") => {
                        let edi: v004010::Transmission<v004010::_315> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "322") => {
                        let edi: v004010::Transmission<v004010::_322> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "404") => {
                        let edi: v004010::Transmission<v004010::_404> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "997") => {
                        let edi: v004010::Transmission<v004010::_997> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("004010", "998") => {
                        let edi: v004010::Transmission<v004010::_998> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("005010", "834") => {
                        let edi: v005010::Transmission<v005010::_834> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("005010", "835") => {
                        let edi: v005010::Transmission<v005010::_835> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("005010", "837") => {
                        let edi: v005010::Transmission<v005010::_837> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    ("005030", "404") => {
                        let edi: v005030::Transmission<v005030::_404> =
                            serde_json::de::from_str(&str).unwrap();
                        format!("{edi}")
                    }
                    _ => {
                        unimplemented!()
                    }
                };
                println!("{edi}");
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

#[test]
fn check_for_una() {
    let str = r#"UNA:+.? 'UNB+UNOC:3+SENDER+CRECEIVER+221121:1422+1291'UNH+"#;
    let result = get_encoding(str);
    println!("{:?}", result);
    assert_eq!(result, Encoding::Edifact);
}

#[test]
fn check_for_unb() {
    let str = r#"UNB+UNOC:3+SNDR+RCVR+221121:1422+1291'UNH+"#;
    let result = get_encoding(str);
    println!("{:?}", result);
    assert_eq!(result, Encoding::Edifact);
}
#[test]
fn check_edifact_cuscar() {
    let str = "UNB+UNOC:3+HKGHKG999+BLI-CUS+221121:0430+336'UNH+321+CUSCAR:D:96B:UN'BGM+85+CUSCAR/202211210430/+9'DTM+137:202211210430:203'RFF+AAZ:SUDU'NAD+MS+HSA'CTA+IC+:DAVID ZHANG/852-34788102'NAD+BA+HSA'TDT+20+246N+1+++++9178393:146:11:MERATUS MEDAN 5:ID'DTM+133:20221122:102'GIS+23'EQD+CN+MRKU7178024::ZZZ+22G1+++5'TSR++2:::2'MEA+AAE+T+KGM:2170'SEL+ML-ID0212928'EQD+CN+MSKU5705452::ZZZ+22G1+++5'TSR++2:::2'MEA+AAE+T+KGM:2180'SEL+ML-ID0212929'EQD+CN+GLDU5592412::ZZZ+22G1++";
    let result = get_edifact_type(str).unwrap();
    println!("{:?}", result);
}

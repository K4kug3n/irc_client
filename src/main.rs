#![feature(str_split_whitespace_remainder)]

use core::panic;
use std::io::prelude::*;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

#[derive(Debug)]
struct Prefix {
    host: String,
    nickname: Option<String>,
    user: Option<String>,
}
#[derive(Debug)]
struct Message {
    prefix: Option<String>,
    command: String,
    params: Vec<String>,
}
#[derive(Debug)]
struct User {
    nickname: String,
    channels: Vec<String>,
}

#[derive(Debug)]
struct Client {
    write_stream: Arc<Mutex<TcpStream>>,
    user: Arc<Mutex<User>>,
}

impl Client {
    fn new(ip: &str, port: u16) -> Client {
        println!("Connecting...");
        let mut receiv_stream = TcpStream::connect((ip, port)).expect("Error on connection");
        println!("Connected !");

        let user = Arc::new(Mutex::new(User {
            nickname: String::new(),
            channels: Vec::new(),
        }));

        let write_stream = Arc::new(Mutex::new(
            receiv_stream
                .try_clone()
                .expect("Error on creating write connection"),
        ));

        let write_stream_reponse = write_stream.clone();
        let user_clone = user.clone();
        thread::spawn(move || {
            receiv_loop(&mut receiv_stream, write_stream_reponse, user_clone);
        });

        Client { write_stream, user }
    }

    fn register(&self, pass: Option<&str>, nick: &str, username: &str, mode: u16, real_name: &str) {
        if pass.is_some() {
            let pass_value = pass.unwrap().to_string();
            write_command(
                &mut self.write_stream.lock().unwrap(),
                "PASS",
                &vec![pass_value],
            );
        }

        let mut user = self.user.lock().unwrap();
        user.nickname = nick.to_string();
        write_command(
            &mut self.write_stream.lock().unwrap(),
            "NICK",
            &vec![nick.to_string()],
        );

        let real_name_param = ":".to_string() + real_name;
        let user_params = vec![
            username.to_string(),
            u16::to_string(&mode),
            "*".to_string(),
            real_name_param,
        ];
        write_command(&mut self.write_stream.lock().unwrap(), "USER", &user_params);
    }
}

fn write(stream: &mut TcpStream, msg: impl Into<String>) {
    let mut str_msg = msg.into();
    str_msg.push_str("\r\n");
    let buf = str_msg.as_bytes();

    let res = stream.write(&buf).expect("Error on write");

    if res != buf.len() {
        panic!("Didn't write the whole message")
    }
}

fn write_command(stream: &mut TcpStream, command: impl Into<String>, params: &Vec<String>) {
    let mut msg = command.into();
    msg.push(' ');
    msg.push_str(params.join(" ").as_str());

    write(stream, msg);
}

fn parse_prefix(prefix: &str) -> Prefix {
    // servername / ( nickname [ [ "!" user ] "@" host ] )
    if prefix.contains('@') {
        let host_split: Vec<&str> = prefix.split('@').collect();

        if host_split[0].contains('!') {
            let user_split: Vec<&str> = host_split[0].split('!').collect();

            return Prefix {
                host: host_split[1].to_string(),
                nickname: Some(user_split[0].to_string()),
                user: Some(user_split[1].to_string()),
            };
        }

        return Prefix {
            host: host_split[1].to_string(),
            nickname: Some(host_split[0].to_string()),
            user: None,
        };
    }

    Prefix {
        host: prefix.to_string(),
        nickname: None,
        user: None,
    }
}

fn parse_server_msg(raw_msg: &String) -> Message {
    let mut iter = raw_msg.split_whitespace();

    let mut prefix: Option<String> = None;
    let mut command = String::new();

    let mut prefix_or_command = iter
        .next()
        .expect("No command in server message")
        .to_string();
    if prefix_or_command.chars().nth(0).unwrap() == ':' {
        // is suffix
        prefix_or_command.remove(0); // remove :
        prefix = Some(prefix_or_command);
        command = iter
            .next()
            .expect("No command in server message")
            .to_string();
    } else {
        // is command
        command = prefix_or_command;
    }

    let mut params = Vec::new();
    while let Some(param) = iter.next() {
        if param.chars().nth(0).unwrap() == ':' {
            // is trailing
            let mut trailing_param = param.to_owned();
            trailing_param.remove(0); // remove :

            let remainder: Option<&str> = iter.remainder();
            if remainder.is_some() {
                trailing_param.push(' ');
                trailing_param.push_str(remainder.unwrap());
            }

            params.push(trailing_param);
            break;
        } else {
            params.push(param.to_owned());
        }
    }

    Message {
        prefix,
        command,
        params,
    }
}

fn handle_notice_msg(msg: &Message, write_stream: Arc<Mutex<TcpStream>>) {
    println!("Notice: {}", msg.params[1]) // TODO: Manage msgtarget ?
}

fn handle_private_msg(msg: &Message, write_stream: Arc<Mutex<TcpStream>>) {
    let prefix = parse_prefix(msg.prefix.clone().unwrap().as_str());
    let from = prefix.nickname.unwrap();

    let version_request  = (0x01 as char).to_string() + "VERSION" + (0x01 as char).to_string().as_str();
    if msg.params[1] == version_request {
        write_command(
            &mut write_stream.lock().unwrap(),
            "NOTICE",
            &vec![from, (0x01 as char).to_string() + "VERSION CustomIRCClient 0.1" + (0x01 as char).to_string().as_str()]
        );

        return
    }

    println!("{} -> {} : {}", from, msg.params[0], msg.params[1]);
}

fn handle_join_msg(msg: &Message, user: &mut User) {
    let prefix = parse_prefix(msg.prefix.clone().unwrap().as_str());
    let nickname = prefix.nickname.unwrap();

    if nickname == user.nickname {
        println!("You join {}", msg.params[0]);
        user.channels.push(msg.params[0].clone());
    } else {
        println!("{} join {}", nickname, msg.params[0]);
    }
}

fn handle_part_msg(msg: &Message, user: &mut User) {
    let prefix = parse_prefix(msg.prefix.clone().unwrap().as_str());
    let nickname = prefix.nickname.unwrap();

    if nickname == user.nickname {
        println!("You leave {}", msg.params[0]);
        user.channels
            .retain(|channel| channel.as_str() != msg.params[0]);

        if user.channels.is_empty() {
            println!("You are not in any channel");
        } else {
            println!("Current channel: {}", user.channels.last().unwrap());
        }
    } else {
        println!("{} leave {}", nickname, msg.params[0]);
    }
}

fn handle_nick_msg(msg: &Message, user: &mut User) {
    let prefix = parse_prefix(msg.prefix.clone().unwrap().as_str());
    let nickname = prefix.nickname.unwrap();

    if nickname == user.nickname {
        println!("You become {}", msg.params[0]);
        user.nickname = msg.params[0].clone();
    } else {
        println!("{} become {}", nickname, msg.params[0]);
    }
}

fn handle_server_msg(
    raw_msg: &String,
    write_stream: Arc<Mutex<TcpStream>>,
    user: Arc<Mutex<User>>,
) {
    let msg = parse_server_msg(raw_msg);

    // TODO: Check number of param ?
    match msg.command.as_str() {
        "NOTICE" => handle_notice_msg(&msg, write_stream),
        "PRIVMSG" => handle_private_msg(&msg, write_stream),
        "ERROR" => {
            println!("Error received from server");
        }
        "PING" => {
            write_command(
                &mut write_stream.lock().unwrap(),
                "PONG".to_string(),
                &msg.params,
            );
        }
        "JOIN" => handle_join_msg(&msg, &mut user.lock().unwrap()),
        "PART" => handle_part_msg(&msg, &mut user.lock().unwrap()),
        "NICK" => handle_nick_msg(&msg, &mut user.lock().unwrap()),

        "MODE" => {}                                 //TODO!
        "001" => println!("{}", msg.params[1]),      // RPL_WELCOME
        "002" => println!("{}", msg.params[1]),      // RPL_YOURHOST
        "003" => println!("{}", msg.params[1]),      // RPL_CREATED
        "004" => println!("(004) {:?}", msg.params), // RPL_MYINFO
        "005" => println!("(005) RPL_BOUNCE"),

        "251" => println!("{}", msg.params[1]), // RPL_LUSERCLIENT
        "252" => println!("{} {}", msg.params[1], msg.params[2]), // RPL_LUSEROP
        "253" => println!("{} {}", msg.params[1], msg.params[2]), // RPL_LUSERUNKNOWN
        "254" => println!("{} {}", msg.params[1], msg.params[2]), // RPL_LUSERCHANNELS
        "255" => println!("{}", msg.params[1]), // RPL_LUSERME
        "265" => println!("{}", msg.params[1]),
        "266" => println!("{}", msg.params[1]),

        "332" => println!("{}", msg.params[1]), // RPL_TOPIC
        "333" => println!("{}", msg.params[1]), // RPL_TOPICWHOTIME

        "353" => {
            println!("In {} {} : {}", msg.params[1], msg.params[2], msg.params[3]);
        }
        "366" => {} // End of the NAMES

        "375" => {}                             // Start of the MOTD
        "372" => println!("{}", msg.params[1]), // MOTD
        "376" => {}                             // End of the MOTD

        "396" => println!("Displayed host: {}", msg.params[1]),

        "476" => println!("{}: {}", msg.params[2], msg.params[1]), // Invalid channel name

        _ => println!("{:?}", msg),
    }
}

fn receiv_loop(
    receiv_stream: &mut TcpStream,
    write_stream: Arc<Mutex<TcpStream>>,
    user: Arc<Mutex<User>>,
) {
    let mut buf = [0; 512];
    let mut remainder = String::new();

    while let Ok(size) = receiv_stream.read(&mut buf) {
        if size == 0 {
            break;
        }

        let received_str =
            remainder.clone() + String::from_utf8_lossy(&buf[..size]).into_owned().as_str();
        remainder = "".to_string();

        let mut messages: Vec<&str> = received_str
            .split("\r\n")
            .filter(|&x| !x.is_empty())
            .collect();

        if (buf[size - 2] != b'\r') && (buf[size - 1] != b'\n') {
            remainder = messages.pop().unwrap().to_string();
        }

        for msg in messages {
            handle_server_msg(&msg.to_owned(), write_stream.clone(), user.clone());
        }
    }
}

fn handle_input(input: String, write_stream: Arc<Mutex<TcpStream>>) {
    let parts: Vec<&str> = input.split_whitespace().collect();

    // TODO: Check number of param ?
    match parts[0] {
        "/join" => {
            write_command(
                &mut write_stream.lock().unwrap(),
                "JOIN".to_string(),
                &vec![parts[1].to_string()],
            );
        }
        "/part" => {
            write_command(
                &mut write_stream.lock().unwrap(),
                "PART".to_string(),
                &vec![parts[1].to_string()],
            );
        }
        "/nick" => {
            write_command(
                &mut write_stream.lock().unwrap(),
                "NICK".to_string(),
                &vec![parts[1].to_string()],
            );
        }
        _ => println!("Command not recognised"),
    }
}

fn write_loop(write_stream: Arc<Mutex<TcpStream>>) {
    loop {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");

        if input.trim() == "/q" {
            write_stream
                .lock()
                .unwrap()
                .shutdown(std::net::Shutdown::Both);
            break;
        }

        if input.trim() == "" {
            continue;
        }

        handle_input(input.trim().to_string(), write_stream.clone());
    }
}

fn main() {
    let ip = "irc.freenode.net";
    let port = 6667;

    let client = Client::new(ip, port);
    client.register(None, "K4k", "guest", 0, "Max R");

    write_loop(client.write_stream);
}

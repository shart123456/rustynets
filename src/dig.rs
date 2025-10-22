// src/dig.rs - Fixed to use hickory_resolver instead of trust_dns_resolver
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::proto::rr::{RecordType, RData};
use std::net::IpAddr;
use std::time::Instant;

pub struct DigOptions {
    pub query_type: RecordType,
    pub nameserver: Option<IpAddr>,
    pub show_stats: bool,
    pub trace: bool,
    pub short: bool,
}

impl Default for DigOptions {
    fn default() -> Self {
        Self {
            query_type: RecordType::A,
            nameserver: None,
            show_stats: true,
            trace: false,
            short: false,
        }
    }
}

pub struct DigResult {
    pub domain: String,
    pub query_type: RecordType,
    pub answers: Vec<String>,
    pub authorities: Vec<String>,
    pub additionals: Vec<String>,
    pub query_time: u128,
    pub server: String,
    pub status: String,
}

impl DigResult {
    pub fn display(&self, options: &DigOptions) {
        if options.short {
            // Short format - just the answers
            for answer in &self.answers {
                println!("{}", answer);
            }
            return;
        }

        println!();
        println!("; <<>> DiG-like Rust Tool <<>> {} {}", self.domain, self.query_type);
        println!(";; global options: +cmd");
        println!(";; Got answer:");
        println!(";; ->>HEADER<<- opcode: QUERY, status: {}, id: -", self.status);
        println!(";; flags: qr rd ra; QUERY: 1, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
                 self.answers.len(), self.authorities.len(), self.additionals.len());
        println!();

        // Question section
        println!(";; QUESTION SECTION:");
        println!(";{}\t\t\tIN\t{}", self.domain, self.query_type);
        println!();

        // Answer section
        if !self.answers.is_empty() {
            println!(";; ANSWER SECTION:");
            for answer in &self.answers {
                println!("{}", answer);
            }
            println!();
        }

        // Authority section
        if !self.authorities.is_empty() {
            println!(";; AUTHORITY SECTION:");
            for authority in &self.authorities {
                println!("{}", authority);
            }
            println!();
        }

        // Additional section
        if !self.additionals.is_empty() {
            println!(";; ADDITIONAL SECTION:");
            for additional in &self.additionals {
                println!("{}", additional);
            }
            println!();
        }

        if options.show_stats {
            println!(";; Query time: {} msec", self.query_time);
            println!(";; SERVER: {}", self.server);
            println!(";; WHEN: {}", chrono::Local::now().format("%a %b %d %H:%M:%S %Z %Y"));
            println!();
        }
    }
}

pub async fn dig(domain: &str, options: DigOptions) -> Result<DigResult, String> {
    let start = Instant::now();

    // Configure resolver based on options
    let (config, opts) = if let Some(ns) = options.nameserver {
        // Use custom nameserver
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: std::net::SocketAddr::new(ns, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        (config, ResolverOpts::default())
    } else {
        // Use system defaults
        (ResolverConfig::default(), ResolverOpts::default())
    };

    let resolver = TokioAsyncResolver::tokio(config.clone(), opts);

    let server_addr = if let Some(ns) = options.nameserver {
        format!("{}#53", ns)
    } else {
        "system default".to_string()
    };

    // Perform the lookup - use generic lookup for all types
    let lookup_result = resolver.lookup(domain, options.query_type).await;

    let query_time = start.elapsed().as_millis();

    match lookup_result {
        Ok(lookup) => {
            let mut answers = Vec::new();

            for record in lookup.record_iter() {
                let rdata = record.data();
                let ttl = record.ttl();
                let name = record.name().to_string();

                let answer_str = match rdata {
                    Some(RData::A(ip)) => format!("{}\t{}\tIN\tA\t{}", name, ttl, ip),
                    Some(RData::AAAA(ip)) => format!("{}\t{}\tIN\tAAAA\t{}", name, ttl, ip),
                    Some(RData::CNAME(cname)) => format!("{}\t{}\tIN\tCNAME\t{}", name, ttl, cname),
                    Some(RData::MX(mx)) => format!("{}\t{}\tIN\tMX\t{} {}", name, ttl, mx.preference(), mx.exchange()),
                    Some(RData::NS(ns)) => format!("{}\t{}\tIN\tNS\t{}", name, ttl, ns),
                    Some(RData::PTR(ptr)) => format!("{}\t{}\tIN\tPTR\t{}", name, ttl, ptr),
                    Some(RData::SOA(soa)) => {
                        format!("{}\t{}\tIN\tSOA\t{} {} {} {} {} {} {}",
                                name, ttl, soa.mname(), soa.rname(),
                                soa.serial(), soa.refresh(), soa.retry(),
                                soa.expire(), soa.minimum())
                    },
                    Some(RData::SRV(srv)) => {
                        format!("{}\t{}\tIN\tSRV\t{} {} {} {}",
                                name, ttl, srv.priority(), srv.weight(),
                                srv.port(), srv.target())
                    },
                    Some(RData::TXT(txt)) => {
                        let text = txt.iter()
                            .map(|b| String::from_utf8_lossy(b).to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        format!("{}\t{}\tIN\tTXT\t\"{}\"", name, ttl, text)
                    },
                    Some(RData::CAA(caa)) => {
                        let value = match caa.value() {
                            hickory_resolver::proto::rr::rdata::caa::Value::Issuer(_issuer_critical, key_values) => {
                                if let Some(kv) = key_values.first() {
                                    format!("{}", kv)
                                } else {
                                    String::new()
                                }
                            },
                            hickory_resolver::proto::rr::rdata::caa::Value::Url(url) => {
                                url.to_string()
                            },
                            hickory_resolver::proto::rr::rdata::caa::Value::Unknown(data) => {
                                String::from_utf8_lossy(data).to_string()
                            },
                        };
                        format!("{}\t{}\tIN\tCAA\t{} {} \"{}\"",
                                name, ttl, caa.issuer_critical() as u8,
                                caa.tag(), value)
                    },
                    Some(rdata) => format!("{}\t{}\tIN\t{}\t{:?}", name, ttl, options.query_type, rdata),
                    None => continue,
                };

                answers.push(answer_str);
            }

            Ok(DigResult {
                domain: domain.to_string(),
                query_type: options.query_type,
                answers,
                authorities: Vec::new(),
                additionals: Vec::new(),
                query_time,
                server: server_addr,
                status: "NOERROR".to_string(),
            })
        }
        Err(e) => {
            // Return error result
            Ok(DigResult {
                domain: domain.to_string(),
                query_type: options.query_type,
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
                query_time,
                server: server_addr,
                status: format!("ERROR: {}", e),
            })
        }
    }
}

pub async fn dig_any(domain: &str, nameserver: Option<IpAddr>) -> Result<Vec<DigResult>, String> {
    let record_types = vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::MX,
        RecordType::NS,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::CAA,
    ];

    let mut results = Vec::new();

    for record_type in record_types {
        let options = DigOptions {
            query_type: record_type,
            nameserver,
            show_stats: false,
            trace: false,
            short: false,
        };

        match dig(domain, options).await {
            Ok(result) => {
                if !result.answers.is_empty() && result.status == "NOERROR" {
                    results.push(result);
                }
            }
            Err(_) => continue,
        }
    }

    Ok(results)
}

// Helper function to parse record type from string
pub fn parse_record_type(type_str: &str) -> Option<RecordType> {
    match type_str.to_uppercase().as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "MX" => Some(RecordType::MX),
        "NS" => Some(RecordType::NS),
        "TXT" => Some(RecordType::TXT),
        "CNAME" => Some(RecordType::CNAME),
        "SOA" => Some(RecordType::SOA),
        "PTR" => Some(RecordType::PTR),
        "SRV" => Some(RecordType::SRV),
        "CAA" => Some(RecordType::CAA),
        "ANY" => Some(RecordType::ANY),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_a_record() {
        let options = DigOptions {
            query_type: RecordType::A,
            ..Default::default()
        };

        let result = dig("google.com", options).await;
        assert!(result.is_ok());

        let dig_result = result.unwrap();
        assert!(!dig_result.answers.is_empty());
    }

    #[tokio::test]
    async fn test_mx_record() {
        let options = DigOptions {
            query_type: RecordType::MX,
            ..Default::default()
        };

        let result = dig("gmail.com", options).await;
        assert!(result.is_ok());
    }
}
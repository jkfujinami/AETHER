pub mod quic;
pub mod stun;
pub mod onion;
pub mod relay;
pub mod gossip;
pub mod gossip_server;
pub mod hint_log;
pub mod seen_cache;
pub mod hint_batcher;
pub mod guard;
pub mod ring;
pub mod relay_list;
pub mod pex;
pub mod addr;
pub mod shared_socket;
pub mod port_mapping;
pub mod punch;
pub mod reachability;
pub mod shaper;
pub mod tunnel;
pub mod connection_pool;
pub mod dandelion; // Dandelion++ 放流元秘匿（3-2）
pub mod epoch; // エポックビーコン（drand 由来の日次シード / 3-4）

pub use quic::{QuicClient, QuicServer, QuicConnection};
pub use stun::StunResolver;
pub use onion::OnionCircuit;
pub use relay::RelayClient;
pub use gossip::GossipClient;
pub use shaper::{TrafficShaper, ShapingConfig, ShapingStrategy};

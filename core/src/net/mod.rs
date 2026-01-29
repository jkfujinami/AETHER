pub mod quic;
pub mod stun;
pub mod onion;
pub mod relay;
pub mod gossip;
pub mod gossip_server;
pub mod shaper;
pub mod tunnel;
pub mod connection_pool;

pub use quic::{QuicClient, QuicServer, QuicConnection};
pub use stun::StunResolver;
pub use onion::OnionCircuit;
pub use relay::RelayClient;
pub use gossip::GossipClient;
pub use shaper::{TrafficShaper, ShapingConfig, ShapingStrategy};

use clap::{Parser, Subcommand};
use aether_core::crypto::identity::Identity;
use std::error::Error;

#[derive(Parser)]
#[command(name = "aether")]
#[command(about = "AETHER Protocol CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new identity
    Init {
        /// Output path for identity file
        #[arg(short, long, default_value = "identity.json")]
        output: String,
    },
    /// Start the AETHER node (Relay/Gossip/Mailbox listener)
    Start {
        /// Port to listen on
        #[arg(short, long, default_value_t = 9000)]
        port: u16,

        /// Entry Relay Address (e.g., 127.0.0.1:8080)
        #[arg(short, long)]
        connect: Option<String>,
    },
    /// Send a message (Test command)
    Send {
        /// Recipient Public ID (Hex)
        #[arg(short, long)]
        to: String,
        /// Message content
        #[arg(short, long)]
        message: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ログ初期化
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Init { output } => {
            println!("Generating new identity...");
            let id = Identity::generate();
            println!("Generated Public ID: {:?}", id.public_id());

            // ファイル保存シミュレーション
            // let json = serde_json::to_string(&id)?;
            // tokio::fs::write(output, json).await?;
            println!("(Simulation) Identity saved to {}", output);
        }
        Commands::Start { port, connect } => {
            println!("Starting AETHER node on port {}...", port);

            // ノードサーバー作成
            // Use fully qualified path or import

            // Identity 生成 (TODO: 永続化されたIdentityをロードする)
            let identity = Identity::generate();
            println!("Node ID: {}", identity.public_id());

            let db_path = std::path::Path::new("./aether_node.db");

            let node = aether_core::node::server::NodeServer::new(*port, identity, db_path)?;

            if let Some(addr) = connect {
                println!("(TODO) Connecting to entry node: {}", addr);
                // logic to connect via node.connect(addr) or similar
            }

            println!("Node running. Press Ctrl+C to stop.");

            // サーバー実行（無限ループ）
            node.run().await?;
        }
        Commands::Send { to, message } => {
            println!("Sending message...");
            println!("  To: {}", to);
            println!("  Content: {}", message);

            println!("Encrypting and creating Hint packet...");
            // ここで SchrodingerMailbox を呼び出すロジックが入る

            println!("(Simulation) Message sent via Onion Routing.");
        }
    }

    Ok(())
}

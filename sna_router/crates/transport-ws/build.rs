fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    std::env::set_var("PROTOC", protoc);
    prost_build::Config::new()
        .compile_protos(
            &[
                "../../../proto/snusnu_routes_v1.proto",
                "../../../proto/snusnu_ws_v1.proto",
            ],
            &["../../../proto"],
        )
        .expect("compile WebSocket protocol");
    println!("cargo:rerun-if-changed=../../../proto/snusnu_routes_v1.proto");
    println!("cargo:rerun-if-changed=../../../proto/snusnu_ws_v1.proto");
}

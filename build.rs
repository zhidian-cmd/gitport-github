// exe 图标资源：embed-resource 3.x 自带 rc 编译，无需系统 rc.exe。
fn main() {
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/icon.ico");
    embed_resource::compile("assets/app.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}

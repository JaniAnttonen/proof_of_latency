use std::ptr::Unique;

#[cfg(target_pointer_width = "32")]
pub type BaseInt = u32;
#[cfg(target_pointer_width = "64")]
pub type BaseInt = u64;

#[derive(Serialize, Deserialize)]
#[serde(remote = "Limb")]
pub struct VDFLimb(pub BaseInt);

#[derive(Serialize, Deserialize)]
#[serde(remote = "Int")]
pub struct VDFInt {
    ptr: Unique<VDFLimb>,
    size: i32,
    cap: u32,
}

// fn str_to_int(input: &str, serializer: S)<S: Serializer> -> Result<Int, S::Error> {
// 
// }
// 
// fn int_to_str(input: &Int) -> &str {
// 
// }

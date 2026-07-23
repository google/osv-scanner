import tarfile, json, hashlib

tar_path = "test-alpine.tar"

with tarfile.open(tar_path) as tar:
    # 1. Get manifest to locate config file
    manifest = json.loads(tar.extractfile("manifest.json").read())
    config_file = manifest[0]["Config"]
    
    # 2. Extract config file and read diff_ids
    config = json.loads(tar.extractfile(config_file).read())
    diff_ids = config["rootfs"]["diff_ids"]

# 3. Print DiffIDs and compute ChainIDs
chain_id = None
for i, diff_id in enumerate(diff_ids):
    if i == 0:
        chain_id = diff_id
    else:
        # ChainID = SHA256(Parent_ChainID + " " + Current_DiffID)
        combined = f"{chain_id} {diff_id}".encode("utf-8")
        chain_id = f"sha256:{hashlib.sha256(combined).hexdigest()}"
    
    print(f"Layer {i + 1}:")
    print(f"  DiffID:  {diff_id}")
    print(f"  ChainID: {chain_id}\n")

# HITT Image Manager Mode

**Image manager mode** (`-r`) helps you **download, retag, push, save, and check** BMC Helix container images on a machine that has **Docker** installed. Typical use is copying images from BMC registries (for example `docker.io/bmchelix/...`) into **your** registry before or during an on-premises deployment.

When the command has more than one word, pass the whole value in **double quotes**:

```bash
bash hitt.sh -r "sync -f images.txt -t myregistry.example.com/myproject"
bash hitt.sh -r "pull -f helix-images.txt -k"
bash hitt.sh -r "verify -i docker.io/bmchelix/ars:26101-RTM -t myregistry.example.com/proj"
bash hitt.sh -r help
```

The **first word** after the quotes is the **action** (`sync`, `pull`, and so on). The rest are options such as **`-f`**, **`-i`**, and **`-t`**.

Built-in summary: `bash hitt.sh -r help` or `bash hitt.sh -h imagemgr`

More help: [https://bit.ly/hitthelp](https://bit.ly/hitthelp)

## Actions

| Action | Description |
|--------|-------------|
| `sync` | Download from the source registry, retag for your registry, push to **`-t`**, then remove the copy from local Docker. |
| `pull` | Download images and keep them on the Docker host. |
| `push` | Retag and push images that are already on the Docker host (for example after **pull**). Local images are not removed. |
| `save` | Download each image and save it as a gzip tar file in the **current directory**, then remove it from local Docker. |
| `load` | Load tar files from the current directory (from **save**), retag, push to **`-t`**, then remove from local Docker. |
| `verify` | Confirm an image is present in the registry. |
| `compare` | Compare checksums on source and target so you can confirm they match. |

## Options (after the action)

| Option | Description |
|--------|-------------|
| `-f` **FILE** | Text file with one image reference per line. Lines starting with `#` and blank lines are skipped. BMC image lists are in Helix product documentation. |
| `-i` **IMAGE** | One image reference, for example `docker.io/bmchelix/ars:26101-RTM`. |
| `-t` **REGISTRY** | Your registry host and optional path (for example `myregistry.example.com/myproject`). Required for **sync**, **push**, **load**, and **compare**. |
| `-s` **REGISTRY** | Prefix added to each line in **`-f`** (not used with **`-i`**). |
| `-n` **N** | How many images to process at once (default **2**). |
| `-k` | Skip registry login when you are already logged in. |
| `-p` **old:new** | Change a path segment in image names, for example `bmchelix:customer` turns `/bmchelix/` into `/customer/`. |

Use **`-f`** or **`-i`**, not both. If you use **`-f`**, the file must exist.

## Usage examples

```bash
# Mirror a list into your registry
bash hitt.sh -r "sync -f images.txt -t myregistry.example.com/myproject"

# Download only (stay logged in with -k)
bash hitt.sh -r "pull -f helix-images.txt -k"

# Check one image in your registry
bash hitt.sh -r "verify -i docker.io/bmchelix/ars:26101-RTM -t myregistry.example.com/proj"

# Run four images in parallel
bash hitt.sh -r "sync -f images.txt -t myregistry.example.com/proj -n 4"

# Retag project path when pushing
bash hitt.sh -r "sync -f images.txt -t customer.registry/acme -p bmchelix:acme"
```

## Registry login

HITT logs in to each registry it needs. If credentials are not already stored, you are prompted.

To run without prompts, set **username** and **password** environment variables before you run HITT:

- **`IMAGEMGR_REGISTRY_USER`** and **`IMAGEMGR_REGISTRY_PASS`** — general registries.
- **`IMAGEMGR_DOCKERIO_USER`** and **`IMAGEMGR_DOCKERIO_PASS`** — Docker Hub (`docker.io`). Use a Docker Hub personal access token as the password.

## Save file names

When you use **save**, tar file names are built from the image reference so characters such as `/` and `:` do not break file names on disk.

## Disk space

Before **pull** or **save**, HITT checks that enough free disk space is available on the host (at least about **10 GB** in the working directory and in Docker’s storage area). This reduces the chance of a run failing halfway through a large list.

## Log files

- **`results.txt`** — progress messages (also shown on screen).
- **`errors.txt`** — problems for individual images. Other images in the same run may still complete. Line numbers help when several images run at once.

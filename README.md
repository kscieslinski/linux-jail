# Sandbox

## Compile
Start with installing dependencies.
```console
$ sudo apt-get install gcc libcap-dev libseccomp-dev libjson-c-dev libssl-dev
```

And now you can just clone the repo and compile the sandbox.c code.

```console
$ git clone https://github.com/kscieslinski/container.git
$ cd container/src
$ gcc sandbox.c -o sandbox -lcap -lseccomp -ljson-c -lcrypto
```

## Usage
You should not modify the source code. All configuration should be done by modyfing profile.json file:

* `mount_root`: almost always you want to leave this empty. In such case, the program will create a root folder inside /tmp/sandbox/unique-container-name/ which will act as root of the filesystem.
* `run_as_user`: it's best to just leave it as 65534 (nobody). Though some applications might require a root to run.
* `pre_script`: you can define path to the script which will be run before starting the sandboxed process. It should copy necessary libraries, binaries, etc. The script is being invoked with path of file system root as $1 argument.
* `whitelisted capabilities`: you can add/disable capabilities.
* `whitelisted_syscalls`: same as above, but for syscalls. Note that the more syscalls a process can use, the easier it is to exploit the kernel from a container.
* `cgroup`: you can speficy the resource limits for the container such as memory limit or cpu shares. You can also limit the maximum number of pids a process can use to protect host from forkbomb.

Once you adjusted profile.json file or you are happy with the default one, you can run the sandbox!

```console
# example usage – invoke interactive /bin/bash inside container
$ sudo ./sandbox ../profile/default-profile.json /bin/bash -i
```

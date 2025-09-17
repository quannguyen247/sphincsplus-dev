qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a76 \
  -m 4G \
  -drive file=../ubuntuARM64.img,if=virtio,format=qcow2 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -cdrom seed/seed.iso \
  -kernel /usr/lib/u-boot/qemu_arm64/uboot.elf \
  -append "root=LABEL=rootfs console=ttyS0" \
  -object rng-random,filename=/dev/urandom,id=rng \
  -device virtio-rng-pci,rng=rng \
  -nographic 

qemu-system-riscv64 \
  -machine virt \
  -cpu max \
  -m 4G \
  -drive file=../ubuntuRV64.img,if=virtio,format=raw \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -cdrom seed/seed.iso \
  -bios /usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin \
  -kernel /usr/lib/u-boot/qemu-riscv64_smode/uboot.elf \
  -append "root=LABEL=rootfs console=ttyS0" \
  -object rng-random,filename=/dev/urandom,id=rng \
  -device virtio-rng-pci,rng=rng \
  -nographic
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func loopFixture(point string) (result error) {
	backing := point + "-backing"
	if strings.ContainsAny(point, "\n\x00") {
		return fmt.Errorf("invalid loop path")
	}
	for _, path := range []string{point, backing} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}
	if err := unix.Mount("tmpfs", backing, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=96m,mode=0755"); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(backing, unix.MNT_DETACH)) }()
	image := filepath.Join(backing, "ext4.img")
	file, err := os.Create(image)
	if err != nil {
		return err
	}
	err = file.Truncate(64 << 20)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		for _, candidate := range []string{"/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"} {
			if mkfs, err = exec.LookPath(candidate); err == nil {
				break
			}
		}
	}
	if err != nil {
		return fmt.Errorf("mkfs.ext4: %w", err)
	}
	if output, err := exec.Command(mkfs, "-q", "-F", image).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4: %w: %s", err, output)
	}
	output, err := exec.Command("losetup", "--find", "--show", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("losetup: %w: %s", err, output)
	}
	device := strings.TrimSpace(string(output))
	defer func() {
		output, err := exec.Command("losetup", "--detach", device).CombinedOutput()
		if err != nil {
			result = errors.Join(result, fmt.Errorf("loop detach: %w: %s", err, output))
		}
	}()
	if err = unix.Mount(device, point, "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(point, unix.MNT_DETACH)) }()
	if err = os.WriteFile(filepath.Join(point, "f"), []byte("loop-canary\n"), 0644); err != nil {
		return err
	}
	fmt.Println("READY loop=" + device)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	<-signals
	return nil
}

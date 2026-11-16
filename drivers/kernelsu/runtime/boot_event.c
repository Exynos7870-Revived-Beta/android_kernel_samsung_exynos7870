#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/workqueue.h>

#include "feature/selinux_hide.h"

#include "policy/allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;
bool ksu_ksud_present __read_mostly = false;

void ksu_set_ksud_present(bool present)
{
	if (READ_ONCE(ksu_ksud_present) == present)
		return;
	WRITE_ONCE(ksu_ksud_present, present);
	pr_info("ksud %s, su goes to %s\n", present ? "installed" : "removed",
		present ? "ksud" : "sh");
}

static void ksu_check_ksud(void)
{
	struct path ksud;
	bool present = !kern_path(KSUD_PATH, 0, &ksud);

	if (present)
		path_put(&ksud);
	ksu_set_ksud_present(present);
}

static void ksu_check_ksud_work_fn(struct work_struct *work)
{
	ksu_check_ksud();
}

static DECLARE_WORK(ksu_check_ksud_work, ksu_check_ksud_work_fn);

/*
 * Safe from atomic context. The /data/adb observer normally keeps
 * ksu_ksud_present current; this is the fallback if it couldn't be set up.
 */
void ksu_recheck_ksud(void)
{
	schedule_work(&ksu_check_ksud_work);
}

extern void ksu_avc_spoof_late_init();

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
bool susfs_is_umount_for_zygote_system_process_enabled = false;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
extern bool susfs_is_auto_add_sus_bind_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
extern bool susfs_is_auto_add_sus_ksu_default_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
extern bool susfs_is_auto_add_try_umount_for_bind_mount_enabled;
#endif

static inline void susfs_on_post_fs_data(void) {
	struct path path;
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (!kern_path(DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS, 0, &path)) {
		susfs_is_umount_for_zygote_system_process_enabled = true;
		path_put(&path);
	}
	pr_info("susfs_is_umount_for_zygote_system_process_enabled: %d\n", susfs_is_umount_for_zygote_system_process_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_bind_mount_enabled: %d\n", susfs_is_auto_add_sus_bind_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_ksu_default_mount_enabled: %d\n", susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_try_umount_for_bind_mount_enabled: %d\n", susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif
}
#endif

void on_post_fs_data(void)
{
	static bool done = false;
	if (done) {
		pr_info("on_post_fs_data already done\n");
		return;
	}
	done = true;
	pr_info("on_post_fs_data!\n");

#ifdef CONFIG_KSU_SUSFS
	susfs_on_post_fs_data();
#endif

	ksu_load_allow_list();
	ksu_observer_init();
	/* After the observer is up, so a ksud install can't slip in between. */
	ksu_check_ksud();
	pr_info("ksud %s\n", ksu_ksud_present ? "present" : "not installed");
	// sanity check, this may influence the performance
	ksu_stop_input_hook_runtime();
	ksu_selinux_hide_handle_post_fs_data();
}

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
extern void ext4_unregister_sysfs(struct super_block *sb);

int nuke_ext4_sysfs(const char *mnt)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		pr_err("nuke path err: %d\n", err);
		return err;
	}

	struct super_block *sb = path.dentry->d_inode->i_sb;
	const char *name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("nuke but module aren't mounted\n");
		path_put(&path);
		return -EINVAL;
	}

	ext4_unregister_sysfs(sb);
	path_put(&path);
	return 0;
}
#else
int nuke_ext4_sysfs(const char *mnt)
{
	return 0;
}
#endif

void on_module_mounted(void)
{
	pr_info("on_module_mounted!\n");
	ksu_module_mounted = true;
}

void on_boot_completed(void)
{
    ksu_boot_completed = true;
    pr_info("on_boot_completed!\n");
    track_throne(true);
    ksu_avc_spoof_late_init();
}

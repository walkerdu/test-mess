/*
 * =====================================================================================
 *
 *       Filename:  linux_namespace_test.cpp
 *
 *    Description:  测试linux namespace相关功能
 *
 *        Version:  1.0
 *        Created:  2022-10-13 18:09:57
 *       Revision:  none
 *       Compiler:  gcc
 *         Coding:  utf-8
 *
 *         Author:  walkerdu
 *   Organization:
 *
 * =====================================================================================
 */

#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#define errExit(msg)        \
    do {                    \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

class LinuxNamespaceTest {
public:
    struct NSStruct {
        int (*child_enter)(void *);
        int clone_flag;
        int (*parent_post_process)(void *);
    };

public:
    LinuxNamespaceTest() {
        namespace_cb_map["NEWUTS"] = {ChildEnterNewUTS, NewUTS_Flag, ParentPostProcNewUTS};
        namespace_cb_map["NEWPID"] = {ChildEnterNewPID, NewPID_Flag, ParentPostProcNewPID};
        namespace_cb_map["NEWIPC"] = {ChildEnterNewIPC, NewIPC_Flag, ParentPostProcNewIPC};
        namespace_cb_map["NEWNET"] = {ChildEnterNewNet, NewNet_Flag, ParentPostProcNewNet};
        namespace_cb_map["NEWCGROUP"] = {ChildEnterNewCgroup, NewCgroup_Flag, ParentPostProcNewCgroup};
        namespace_cb_map["NEWNS"] = {ChildEnterNewMount, NewMount_Flag, ParentPostProcNewMount};
        namespace_cb_map["NEWUSER"] = {ChildEnterNewUser, NewUser_Flag, ParentPostProcNewUser};
    }

    NSStruct *GetCloneInfo(std::string &namespace_type) {
        auto itr = namespace_cb_map.find(namespace_type);
        if (itr == namespace_cb_map.end()) {
            return nullptr;
        }

        return &itr->second;
    }

    static int ChildEnterNewUTS(void *arg) {
        struct utsname uts;

        /* Change hostname in UTS namespace of child */

        if (sethostname((const char *)arg, strlen((const char *)arg)) == -1) errExit("sethostname");

        /* Retrieve and display hostname */

        if (uname(&uts) == -1) errExit("uname");
        printf("uts.nodename in child:  %s\n", uts.nodename);

        /* Keep the namespace open for a while, by sleeping.
           This allows some experimentation--for example, another
           process might join the namespace. */

        sleep(200);

        return 0; /* Child terminates now */
    }

    static int ChildEnterNewPID(void *arg) {
        pid_t pid = getpid();
        pid_t ppid = getppid();
        printf("in child: pid=%d\n", pid);
        printf("in child: parent_pid=%d\n", ppid);

        sleep(200);
        return 0;
    }

    static int ChildEnterNewIPC(void *arg) {
        key_t key = 0x111111;
        size_t size = 128 * 1024;
        int shmid = shmget(key, size, IPC_CREAT | IPC_EXCL | 0654);
        if (shmid < 0) {
            if (errno != EEXIST) {
                printf("in child: shmget create failed, key=%d, error=%s\n", key, strerror(errno));
                return -1;
            }

            shmid = shmget(key, size, 0644);
            if (shmid < 0) {
                printf("in child: shm exists, shmget failed, key=%d, error=%s\n", key, strerror(errno));
                return -2;
            }
        }
        void *p = shmat(shmid, NULL, 0);
        if (!p) {
            printf("in child: shmat failed, shmid=%x key=%d, error=%s\n", shmid, key, strerror(errno));
            return -3;
        }

        printf("in child: shmid=%d, key=0x%x\n", shmid, key);

        key = 0x2222222;
        shmid = shmget(key, size, IPC_CREAT | IPC_EXCL | 0654);
        printf("in child: shmid=%d, key=0x%x\n", shmid, key);

        // FILE *fp = popen("ipcs -m", "r");
        // if (!fp) {
        //    printf("in child: popen failed, error=%s\n", strerror(errno));
        //    return -3;
        //}

        // std::string ipcs_string;
        // char buff[1024];
        // while (fgets(buff, sizeof(buff), fp)) {
        //    ipcs_string += buff;
        //}
        // pclose(fp);

        printf("in child: ipcs -m info:\n");
        system("ipcs -m");

        sleep(200);
        return 0;
    }

    static int ChildEnterNewNet(void *arg) {
        printf("in child:\n");
        system("ip address");

        sleep(200);
        return 0;
    }

    static int ChildEnterNewCgroup(void *arg) {
        printf("in child:\n");

        pid_t pid = getpid();
        std::string cmd = "cat /proc/" + std::to_string(pid) + "/cgroup";
        system(cmd.c_str());

        sleep(200);
        return 0;
    }

    static int ChildEnterNewMount(void *arg) {
        printf("in child:\n");

        system("mkdir -p /rootfs/data");
        system("mount --bind . /rootfs/data");
        system("mount");

        sleep(200);
        return 0;
    }

    static int ChildEnterNewUser(void *arg) {
        printf("in child:\n");
        system("id");

        // 等待父进程设置uid_map
        sleep(2);
        printf("in child: after parent set uid_map\n");
        system("id");

        sleep(200);
        return 0;
    }

    static int ParentPostProcNewUser(void *arg) {
        printf("in parent:\n");
        system("id");

        pid_t *pid = (pid_t*)arg;
        std::string cmd = "echo '0 1001 1' > /proc/" + std::to_string(*pid) + "/uid_map";
        system(cmd.c_str());

        return 0;
    }

    static int ParentPostProcNewMount(void *arg) {
        printf("in parent:\n");
        system("mount");

        return 0;
    }

    static int ParentPostProcNewUTS(void *arg) {
        struct utsname uts;
        /* Display hostname in parent's UTS namespace. This will be
           different from hostname in child's UTS namespace. */

        if (uname(&uts) == -1) errExit("uname");
        printf("uts.nodename in parent: %s\n", uts.nodename);

        return 0;
    }

    static int ParentPostProcNewNet(void *arg) {
        printf("in parent:\n");
        system("ip address");
        return 0;
    }

    static int ParentPostProcNewCgroup(void *arg) {
        printf("in parent:\n");

        pid_t pid = getpid();
        std::string cmd = "cat /proc/" + std::to_string(pid) + "/cgroup";
        system(cmd.c_str());

        return 0;
    }

    static int ParentPostProcNewPID(void *arg) { return 0; }
    static int ParentPostProcNewIPC(void *arg) { return 0; }

    static const int NewUTS_Flag = CLONE_NEWUTS | SIGCHLD;
    static const int NewPID_Flag = CLONE_NEWPID | SIGCHLD;
    static const int NewIPC_Flag = CLONE_NEWIPC | SIGCHLD;
    static const int NewNet_Flag = CLONE_NEWNET | SIGCHLD;
    static const int NewCgroup_Flag = CLONE_NEWCGROUP | SIGCHLD;
    static const int NewMount_Flag = CLONE_NEWNS | SIGCHLD;
    static const int NewUser_Flag = CLONE_NEWUSER | SIGCHLD;

    std::map<std::string, NSStruct> namespace_cb_map;
};

int main(int argc, char *argv[]) {
    std::map<std::string, std::vector<std::string> > cmd_map = {{"NEWUTS", {"child-hostanme"}},
                                                                {"NEWPID", {}},
                                                                {"NEWIPC", {}},
                                                                {"NEWNET", {}},
                                                                {"NEWCGROUP", {}},
                                                                {"NEWUSER", {}},
                                                                {"NEWNS", {}}};

    auto usage_lmd = [argv, &cmd_map]() {
        for (auto &pval : cmd_map) {
            std::string params;
            for (auto &param : pval.second) {
                params += " " + param;
            }

            std::cout << argv[0] << " " << pval.first << " " << params << std::endl;
        }
    };

    if (argc < 2) {
        fprintf(stderr, "Usage: \n");
        usage_lmd();
        exit(EXIT_SUCCESS);
    }

    std::string namespace_type = argv[1];
    auto itr = cmd_map.find(namespace_type);
    if (itr == cmd_map.end() || argc != itr->second.size() + 2) {
        fprintf(stderr, "Usage: \n");
        usage_lmd();
        exit(EXIT_SUCCESS);
    }

    char *stack;    /* Start of stack buffer */
    char *stackTop; /* End of stack buffer */
    pid_t pid;

    /* Allocate stack for child */

    const int32_t STACK_SIZE = 1024 * 1024; /* Stack size for cloned child */
    stack = (char *)malloc(STACK_SIZE);
    if (stack == NULL) errExit("malloc");

    stackTop = stack + STACK_SIZE; /* Assume stack grows downward */

    /* Create child that has its own UTS namespace;
        child commences execution in childFunc() */

    auto ns_test = LinuxNamespaceTest();
    LinuxNamespaceTest::NSStruct *namespace_info = ns_test.GetCloneInfo(namespace_type);
    if (nullptr == namespace_info) {
        printf("GetCloneInfo(%s) failed", namespace_type.c_str());
        exit(EXIT_FAILURE);
    }

    pid = clone(namespace_info->child_enter, stackTop, namespace_info->clone_flag, argv[2]);
    if (pid == -1) errExit("clone");

    printf("in parent: clone() returned child pid=%ld\n", (long)pid);

    /* Parent falls through to here */

    sleep(1); /* Give child time to change its hostname */

    if(0 == strcmp(argv[1], "NEWUSER")) {
        namespace_info->parent_post_process((void*)&pid);
    } else {
        namespace_info->parent_post_process(nullptr);
    }

    if (waitpid(pid, NULL, 0) == -1) /* Wait for child */
        errExit("waitpid");
    printf("child has terminated\n");

    exit(EXIT_SUCCESS);
}

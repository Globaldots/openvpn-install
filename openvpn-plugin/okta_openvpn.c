#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>

#include "openvpn-plugin.h"

#define SCRIPT_PATH PREFIX "/okta_openvpn.py"

struct context
{
    char *okta_host;
    char *okta_cid;
    char *aws_secret;
};

static const char *
get_env(const char *name, const char *envp[])
{
    int i, namelen;
    const char *cp;

    if (envp)
    {
        namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

static int
auth_user_pass_verify(struct context *ctx, const char *args[], const char *envp[])
{
    int pid;
    const char *control, *username, *provider, *password;
    char *argv[] = {SCRIPT_PATH, NULL};

    control = get_env("auth_control_file", envp);
    username = get_env("X509_0_emailAddress", envp);
    provider = get_env("username", envp);
    password = get_env("password", envp);

    if (!control || !username || !provider || !password)
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    pid = fork();
    if (pid < 0)
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (pid > 0)
    {
        int status;

        /* openvpn process forked ok, wait for first child to exit and return its status */
        pid = waitpid(pid, &status, 0);
        if (pid < 0)
        {
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if (WIFEXITED(status))
        {
            return WEXITSTATUS(status);
        }

        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    pid = fork();
    if (pid < 0)
    {
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if (pid > 0)
    {
        /* first child forked ok, pass deferred return up to parent openvpn process */
        exit(OPENVPN_PLUGIN_FUNC_DEFERRED);
    }

    /* second child daemonizes so PID 1 can reap */
    umask(0);
    setsid();
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    if (ctx->okta_host && ctx->okta_cid && ctx->aws_secret)
    {
        setenv("okta_host", ctx->okta_host, 1);
        setenv("okta_cid", ctx->okta_cid, 1);
        setenv("aws_secret", ctx->aws_secret, 1);
    }

    setenv("control", control, 1);
    setenv("username", username, 1);
    setenv("provider", provider, 1);
    setenv("password", password, 1);

    execvp(argv[0], argv);
    exit(1);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v2(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[], void *per_client_context, struct openvpn_plugin_string_list **return_list)
{
    struct context *ctx = (struct context *)handle;

    if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
    {
        return auth_user_pass_verify(ctx, argv, envp);
    }
    else
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v2(unsigned int *type_mask, const char *argv[], const char *envp[], struct openvpn_plugin_string_list **return_list)
{
    struct context *ctx;

    ctx = (struct context *)calloc(1, sizeof(struct context));

    if (argv[1] && argv[2] && argv[3])
    {
        ctx->okta_host = strdup(argv[1]);
        ctx->okta_cid = strdup(argv[2]);
        ctx->aws_secret = strdup(argv[3]);
    }

    *type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    return (openvpn_plugin_handle_t)ctx;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct context *ctx = (struct context *)handle;

    free(ctx->okta_host);
    free(ctx->okta_cid);
    free(ctx->aws_secret);
    free(ctx);
}
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <readline/readline.h>
#include <readline/history.h>

#define MAX_ARGS 64

void setup_signals(){
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
}

typedef struct {
	pid_t pid;
	pid_t pgid;
	int status;
	char cmd[256];
} Job;

Job jobs[64];
int job_count = 0;
int last_exit = 0;
int is_interactive = 0;
pid_t shell_pgid;

void launch_job(char **argv, int background){
	pid_t pid = fork();

	if (pid == 0){
		pid_t pgid = getpid();
		setpgid(0,pgid);

		if (is_interactive && !background)
			tcsetpgrp(STDIN_FILENO, pgid);

		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGTSTP, SIG_DFL);

		execvp(argv[0], argv);
		perror(argv[0]);
		exit(1);
	}

	setpgid(pid, pid);

	if (!background) {
		if (is_interactive)
			tcsetpgrp(STDIN_FILENO, pid);

		int status;
		waitpid(pid, &status, WUNTRACED);
		if (WIFEXITED(status))
			last_exit = WEXITSTATUS(status);

		if (is_interactive)
			tcsetpgrp(STDIN_FILENO, shell_pgid);
	} else {
		Job j = {pid, pid, 0, ""};
		strncpy(j.cmd, argv[0], sizeof(j.cmd) - 1);
		jobs[job_count++] = j;
		printf("[%d] %d\n", job_count, pid);
	}
}

void builtin_jobs(){
	for (int i = 0; i<job_count; i++){
		printf("[%d] %d %s\n", i+1, jobs[i].pid, jobs[i].cmd);
	}
}

void builtin_fg(int job_num){
	if (job_num < 1 || job_num > job_count) {
		printf("fg: no such job\n");
		return;
	}
	Job *j = &jobs[job_num-1];
	if (is_interactive)
		tcsetpgrp(STDIN_FILENO, j->pgid);
	kill(-j->pgid, SIGCONT);
	waitpid(j->pid, NULL, WUNTRACED);
	if (is_interactive)
		tcsetpgrp(STDIN_FILENO, shell_pgid);
}

void builtin_bg(int job_num){
	if (job_num < 1 || job_num > job_count) {
		printf("bg: no such job\n");
		return;
	}
	Job *j = &jobs[job_num-1];
	kill(-j->pgid, SIGCONT);
	printf("[%d] %d resumed\n", job_num, j->pid);
}

char *expand(char *token){
	if (token[0]!='$') return token;

	char *name = token + 1;

	if (strcmp(name, "?") == 0) {
		static char buf[16];
		snprintf(buf, sizeof(buf), "%d", last_exit);
		return buf;
	}

	char *val = getenv(name);
	return val ? val: "";
}

void build_prompt(char *out, size_t outsize){
	char cwd[512];
	char host[64];
	struct passwd *pw = getpwuid(getuid());

	gethostname(host, sizeof(host));
	getcwd(cwd, sizeof(cwd));

	char *home = getenv("HOME");
	char *dir = cwd;

	if (home && strncmp(cwd, home, strlen(home)) == 0)
		dir = cwd + strlen(home) - 1, dir[0] = '~';

	snprintf(out, outsize, "\033[1;32m%s@%s\033[0m:\033[1;34m%s\033[0m$ ",
	         pw->pw_name, host, dir);
}

int tokenize(char *line, char **argv) {
    int argc = 0;
    char *p = line, buf[1024];

    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        int i = 0;
        char quote = 0;

        while (*p && (quote || (*p != ' ' && *p != '\t'))) {
            if (*p == '\\' && !quote) { p++; buf[i++] = *p++; }
            else if (*p == '"' || *p == '\'') {
                if (!quote) quote = *p++;
                else if (*p == quote) { quote = 0; p++; }
                else buf[i++] = *p++;
            } else {
                buf[i++] = *p++;
            }
        }
        buf[i] = '\0';
        argv[argc++] = strdup(buf);
    }

    argv[argc] = NULL;
    return argc;
}

int main() {
    setup_signals();

    shell_pgid = getpid();
    is_interactive = isatty(STDIN_FILENO);

    if (is_interactive) {
        // Wait until we're in the foreground, in case we were
        // launched by a job-control-aware parent (e.g. another shell).
        while (tcgetpgrp(STDIN_FILENO) != (shell_pgid = getpgrp()))
            kill(-shell_pgid, SIGTTIN);

        setpgid(shell_pgid, shell_pgid);
        tcsetpgrp(STDIN_FILENO, shell_pgid);
    }

    using_history();  

    char *argv[MAX_ARGS];
    int   argc;

    while (1) {
        char prompt[600];
        build_prompt(prompt, sizeof(prompt));

        char *line = readline(prompt);
        if (!line) break;             

        if (*line) add_history(line);

        argc = tokenize(line, argv);
        if (argc == 0) {
            free(line);
            continue;
        }

     
        int background = 0;
        if (strcmp(argv[argc - 1], "&") == 0) {
            background = 1;
            argv[--argc] = NULL;
        }

       
        for (int i = 0; i < argc; i++)
            argv[i] = expand(argv[i]);

       
        if (strcmp(argv[0], "exit") == 0) {
            free(line);
            break;
        }
        else if (strcmp(argv[0], "cd") == 0) {
            if (chdir(argv[1] ? argv[1] : getenv("HOME")) != 0)
                perror("cd");
        }
        else if (strcmp(argv[0], "export") == 0 && argv[1]) {
            putenv(strdup(argv[1]));
        }
        else if (strcmp(argv[0], "jobs") == 0) {
            builtin_jobs();
        }
        else if (strcmp(argv[0], "fg") == 0 && argv[1]) {
            builtin_fg(atoi(argv[1] + 1));   
        }
        else if (strcmp(argv[0], "bg") == 0 && argv[1]) {
            builtin_bg(atoi(argv[1] + 1));
        }
        else {
            launch_job(argv, background);
        }

        free(line);
    }

    printf("\n");
    return 0;
}

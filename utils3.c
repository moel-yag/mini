#include "../includes/minishell.h"
/*
// in execution/utils3.c
else if (redir_info->type == TOKEN_HEREDOC)
		{
			int fd = handle_heredoc(redir_info->filename);
			if (fd < 0)
				return (1);
			if (dup2(fd, STDIN_FILENO) == -1)
				return (close(fd), 1);
			close(fd);
		}

int	handle_heredoc(const char *delimiter)
{
    char	*line = NULL;
    size_t	len = 0;
    int		fd;
    char	tmp_name[] = "/tmp/minishell_heredoc_XXXXXX";

    fd = mkstemp(tmp_name);
	if (fd == -1)
        return (-1);
    unlink(tmp_name);
    while (1)
    {
        write(1, "> ", 2);
        if (getline(&line, &len, stdin) == -1)
            break ;
		line[strcspn(line, "\n")] = 0;
		if (strcmp(line, delimiter) == 0)
			break;
		write(fd, line, strlen(line));
		write(fd, "\n", 1);
        // write(fd, line, strlen(line));
    }
    free(line);
    lseek(fd, 0, SEEK_SET);
    return (fd);
}

*/
static int	ft_strcmp(const char *s1, const char *s2)
{
    size_t	i;

    i = 0;
    while (s1[i] && s2[i])
    {
        if (s1[i] != s2[i])
            return ((unsigned char)s1[i] - (unsigned char)s2[i]);
        i++;
    }
    return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

int	handle_heredoc(const char *delimiter)
{
    char	*line;
    int		fd;
    char	tmp_name[] = "/tmp/.heredocXXXXXX";

    fd = mkstemp(tmp_name);
    if (fd == -1)
        return (-1);
    unlink(tmp_name);
    while (1)
    {
        write(1, "> ", 2);
        line = NULL;
        if (getline(&line, (size_t[]){0}, stdin) == -1)
        {
            free(line);
            break ;
        }
        if (line && line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';
        if (ft_strcmp(line, delimiter) == 0)
        {
            free(line);
            break ;
        }
        write(fd, line, strlen(line));
        write(fd, "\n", 1);
        free(line);
    }
    lseek(fd, 0, SEEK_SET);
    return (fd);
}

static void	execute_child_external(t_external_data *data, char **cmd,
		t_list *redir, char **env)
{
	int	err;

	if (redir && handle_redirections(redir) != 0)
		ft_exit_withclear(1);
	if (str_ichr(cmd[0], '/') > -1)
		data->path = cmd[0];
	else
		data->path = get_path(cmd[0], env);
	if (execve(data->path, cmd, env) == -1)
	{
		err = errno;
		exec_error(err, cmd);
	}
}

int	condition(t_external_data *data, char **cmd, t_list *redir, char **env)
{
	if (data->pid < 0)
	{
		perror("Fork failed");
		return (-1);
	}
	else if (data->pid == 0)
	{
		signal(SIGINT, SIG_DFL);
		execute_child_external(data, cmd, redir, env);
		ft_exit_withclear(0);
	}
	return (0);
}

static int	execute_external_cmd(t_execute *exec, char **cmd, t_list *redir,
		char **env)
{
	t_external_data	data;

	data.pid = fork();
	if (condition(&data, cmd, redir, env) == -1)
		return (-1);
	waitpid(data.pid, &data.status, 0);
	if (WIFEXITED(data.status))
		exec->exit_status = WEXITSTATUS(data.status);
	else if (WIFSIGNALED(data.status))
	{
		exec->exit_status = 128 + WTERMSIG(data.status);
		if (exec->exit_status == 128 + SIGINT
			|| exec->exit_status == 128 + SIGQUIT)
			write (1, "\n", 1);
	}
	else if (WIFSTOPPED(data.status))
		exec->exit_status = 128 + WSTOPSIG(data.status);
	return (exec->exit_status);
}

int	execute_command(t_execute *exec, char **cmd, t_list *redir, char **env)
{
	if (is_builtin(cmd[0]))
	{
		if (exec->nb_pipes > 0)
			return (execute_builtin_piped(exec, cmd, redir));
		else
			return (execute_builtin_direct(exec, cmd, redir));
	}
	else
	{
		return (execute_external_cmd(exec, cmd, redir, env));
	}
}

int	validate_and_split(char *arg, char **name, char **value)
{
	char	*eq_pos;

	eq_pos = ft_strchr(arg, '=');
	if (eq_pos)
	{
		*name = ft_substr(arg, 0, eq_pos - arg);
		*value = ft_strdup(eq_pos + 1);
	}
	else
	{
		*name = ft_strdup(arg);
		*value = NULL;
	}
	if (!is_valid_env_name(*name))
{
    ft_putstr_fd("minishell: export: `", STDERR_FILENO);
    ft_putstr_fd(arg, STDERR_FILENO);
    ft_putstr_fd("': not a valid identifier\n", STDERR_FILENO);
    if (*name)
        free(*name);
    if (*value)
        free(*value);
    return (1);
}
	return (0);
}

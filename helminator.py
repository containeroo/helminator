import base64
import logging
import logging.handlers
import os
import re
import sys
from collections import namedtuple
from pathlib import Path
from typing import List

import urllib3

__version__ = "2.0.0"

ansible_chart_repos, ansible_helm_charts, chart_updates = [], [], []
errors = False

Pattern = namedtuple("Pattern", ["with_items", "mr_title",])
pattern = Pattern(
    re.compile(r"^{{.*\.(\w+) }}"),  # with_items
    r"^(Update {CHART_NAME} chart to )v?(\d+.\d+.\d+).*",  # mr_title
)

helm_task_names = ['community.kubernetes.helm', 'helm']
helm_repository_task_names = ['community.kubernetes.helm_repository', 'helm_repository']

Templates = namedtuple("templates", ["branch_name", "merge_request_title", "description", "chart_version", "slack_notification",])
templates = Templates(
    "helminator/{CHART_NAME}",  # branche_name
    "Update {CHART_NAME} chart to {NEW_VERSION}",  # merge_request_title
    "| File | Chart | Change |\n| :-- | :-- | :-- |\n{FILE_PATH} | {CHART_NAME} | `{OLD_VERSION}` -> `{NEW_VERSION}`",  # description
    "chart_version: {VERSION}",  # chart_version
    "{LINK}{CHART_NAME}: `{OLD_VERSION}` -&gt; `{NEW_VERSION}`",  # slack_notification
)

try:
    import gitlab
    import requests
    import semver
    import yaml
    from requests import HTTPError
    from slack import WebClient
    from slack.errors import SlackApiError
except Exception:
    sys.stderr.write("requirements are not satisfied! see 'requirements.txt'\n")
    sys.exit(1)


def check_env_vars():
    ci_dir_project = os.environ.get("CI_PROJECT_DIR")
    search_dir = os.environ.get("HELMINATOR_ANSIBLE_ROOT_DIR", ci_dir_project)
    vars_file = os.environ.get("HELMINATOR_ANSIBLE_VARS_FILE")
    enable_prereleases = os.environ.get("HELMINATOR_ENABLE_PRERELEASES", "false").lower() == "true"

    verify_ssl = os.environ.get("HELMINATOR_VERIFY_SSL", "false").lower() == "true"
    loglevel = os.environ.get("HELMINATOR_LOGLEVEL", "info").lower()

    enable_mergerequests = os.environ.get("HELMINATOR_ENABLE_MERGEREQUESTS", "true").lower() == "true"
    gitlab_token = os.environ.get("HELMINATOR_GITLAB_TOKEN")
    remove_source_branch = os.environ.get("HELMINATOR_GITLAB_REMOVE_SOURCE_BRANCH", "true").lower() == "true"
    squash = os.environ.get("HELMINATOR_GITLAB_SQUASH_COMMITS", "false").lower() == "true"

    assignees = os.environ.get("HELMINATOR_GITLAB_ASSIGNEES")
    assignees = ([] if not assignees else [a.strip() for a in assignees.split(",") if a])

    slack_token = os.environ.get("HELMINATOR_SLACK_API_TOKEN")
    slack_channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")

    gitlab_url = os.environ.get("CI_SERVER_URL")
    project_id = os.environ.get("CI_PROJECT_ID")
    if not str(project_id).isdigit():
        raise EnvironmentError("environment variable 'CI_PROJECT_ID' must be int!")

    if not search_dir:
        raise EnvironmentError("environment variable 'HELMINATOR_ROOT_DIR' not set!")

    if slack_token and not slack_channel:
        raise EnvironmentError("environment variable 'HELMINATOR_SLACK_CHANNEL' not set!")

    if enable_mergerequests and not gitlab_token:
        raise EnvironmentError("environment variable 'GITLAB_TOKEN' not set!")

    Env_vars = namedtuple('Env_vars', ['search_dir',
                                       'vars_file',
                                       'enable_prereleases',
                                       'verify_ssl',
                                       'loglevel',
                                       'enable_mergerequests',
                                       'gitlab_token',
                                       'remove_source_branch',
                                       'squash',
                                       'assignees',
                                       'slack_token',
                                       'slack_channel',
                                       'gitlab_url',
                                       'project_id',
                                       ]
    )

    return Env_vars(
        search_dir,
        vars_file,
        enable_prereleases,
        verify_ssl,
        loglevel,
        enable_mergerequests,
        gitlab_token,
        remove_source_branch,
        squash,
        assignees,
        slack_token,
        slack_channel,
        gitlab_url,
        int(project_id),
    )


def setup_logger(loglevel='info'):
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    urllib3.disable_warnings()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if loglevel == "critical":
        loglevel = logging.CRITICAL
    elif loglevel == "error":
        loglevel = logging.ERROR
    elif loglevel == "warning":
        loglevel = logging.WARNING
    elif loglevel == "info":
        loglevel = logging.INFO
    elif loglevel == "debug":
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    default_format = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(message)s")
    debug_format = logging.Formatter("%(asctime)s [%(filename)s:%(lineno)s - %(funcName)-20s ] %(message)s")

    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(loglevel)
    console_logger.setFormatter(debug_format if loglevel == logging.DEBUG else default_format)
    root_logger.addHandler(console_logger)


def process_yaml(search_dir, additional_vars=None, enable_prereleases=False):
    """iterate over directory and extract Helm chart name and version

    Keyword Arguments:
        search_dir {str} -- path to directory
        additional_vars {list} -- list with dicts with additional vars
        enable_prereleases {bool} -- process pre-releases (default: False)
    """
    search_dir = Path(search_dir)
    if not search_dir.is_dir():
        raise NotADirectoryError(f"'{search_dir}' is not a directory")

    for item in search_dir.glob("**/*"):
        if not item.is_file():
            continue
        if item.suffix not in ['.yml', '.yaml']:
            continue
        if 'collections/' in str(item.absolute()):
            continue
        try:
            get_ansible_helm(path=item.absolute(),
                             additional_vars=additional_vars,
                             enable_prereleases=enable_prereleases)
        except Exception as e:
            logging.error("unexpected exception while parsing yaml "
                          f"'{item.absolute}'. {str(e)}")


def get_ansible_helm(path, additional_vars=None, enable_prereleases=False):
    """load ansible yamls and search for Helm chart name and version

    Keyword Arguments:
        path {str} -- path to yaml
        vars {list} -- list with dicts with extra vars
        enable_prereleases {bool} -- process pre-releases (default: False)
    """

    def _parse_ansible_helm_task(item):
        for task_name in helm_task_names:
            if item.get(task_name):
                _extract_ansible_helm_task(chart_ref=item[task_name]['chart_ref'],
                                           chart_version=item[task_name]['chart_version'] if
                                           item[task_name].get('chart_version') else None)

    def _parse_ansible_helm_repository_task(item):
        for task_name in helm_repository_task_names:
            if item.get(task_name):
                with_items = item.get('with_items')

                if additional_vars and isinstance(with_items , str):
                    search = re.sub(r'[^\w]', '', with_items)
                    with_items = additional_vars.get(search)

                if not isinstance(with_items, list):
                    with_items = None

                _extract_ansible_helm_repository_task(
                    repo_name=item[task_name]['name'],
                    repo_url=item[task_name]['repo_url'],
                    with_items=with_items)

    def _extract_ansible_helm_task(chart_ref, chart_version):
        if not any(chart for chart in ansible_helm_charts if chart == chart_ref):
            segments = chart_ref.split('/')
            if len(segments) > 2:
                return
            repo_name = segments[0]
            chart_name = segments[-1]
            if not chart_version or not semver.VersionInfo.isvalid(chart_version.lstrip('v')):
                logging.warning(f"ansible helm task '{repo_name}/{chart_name}' has"
                                f" an invalid version '{chart_version}'")
                return
            version = semver.VersionInfo.parse(chart_version.lstrip('v'))
            if version.prerelease and not enable_prereleases:
                logging.warning(f"skipping ansible helm task '{repo_name}/{chart_name}' with version '{chart_version}'"
                                "because it is a pre-release")
                return
            chart = {
                'name': chart_name,
                'version': chart_version,
                'repo': repo_name,
                'yaml_path': yaml_path
            }
            logging.debug(f"found ansible helm task '{repo_name}/{chart_name}' with version '{chart_version}'")
            ansible_helm_charts.append(chart)

    def _extract_ansible_helm_repository_task(repo_name, repo_url, with_items):
        if not any(repo for repo in ansible_chart_repos if repo['name'] == repo_name):
            if with_items:
                item_repo_name = re.findall(pattern.with_items, repo_name)
                if not item_repo_name:
                    logging.warning(f"could not find ansible helm_repository name in '{repo_name}'")
                    return
                item_repo_name = item_repo_name[0]

                item_repo_url = re.findall(pattern.with_items, repo_url)
                if not item_repo_url:
                    logging.warning(f"could not find ansible helm_repository url in '{repo_url}'")
                    return
                item_repo_url = item_repo_url[0]

                for _item in with_items:
                    repo = {
                        'name': _item[item_repo_name],
                        'url': _item[item_repo_url].rstrip('/')
                    }
                    logging.debug(
                        f"found ansible helm_repository task '{_item[item_repo_name]}' with "
                        f"url '{_item[item_repo_url]}'")
                    ansible_chart_repos.append(repo)
                return

            if pattern.with_items.match(repo_name):
                return

            repo = {
                'name': repo_name,
                'url': repo_url.rstrip('/')
            }
            logging.debug(f"found ansible helm_repository task '{repo_name}' with url '{repo_url}'")
            ansible_chart_repos.append(repo)

    def _extract_tasks(key: str, item: dict):
        for sub_item in item[key]:
            if not isinstance(sub_item, dict):
                continue
            if sub_item.get('block'):
                _extract_tasks(key='block', item=sub_item)
            if sub_item.get('community.kubernetes.helm') or sub_item.get('helm'):
                _parse_ansible_helm_task(item=sub_item)
            if sub_item.get('community.kubernetes.helm_repository') or sub_item.get('helm_repository'):
                _parse_ansible_helm_repository_task(item=sub_item)

    try:
        with open(path) as stream:
            tasks = yaml.safe_load(stream)
    except Exception:
        # ignore unparsable yaml files, since ansible already does this
        return

    yaml_path = path
    for task in tasks:
        if not isinstance(task, dict):
            continue
        if task.get('pre_tasks'):
            _extract_tasks(key='pre_tasks', item=task)
        if task.get('tasks'):
            _extract_tasks(key='tasks', item=task)
        if task.get('block'):
            _extract_tasks(key='block', item=task)
        if task.get('community.kubernetes.helm') or task.get('helm'):
            _parse_ansible_helm_task(item=task)
        if task.get('community.kubernetes.helm_repository') or task.get('helm_repository'):
            _parse_ansible_helm_repository_task(item=task)


def get_chart_updates(enable_prereleases=False, verify_ssl=True):
    """get Helm chart yaml from repo and compare chart name and version with ansible
    chart name and version

    Keyword Arguments:
         enable_prereleases {bool} -- process pre-releases (default: False)
         verify_ssl {bool} -- check ssl certs (default: True)
    """
    global errors
    for ansible_chart_repo in ansible_chart_repos:
        ansible_helm_charts_matching = [chart for chart in ansible_helm_charts if
                                        chart['repo'] == ansible_chart_repo['name']]

        if not ansible_helm_charts_matching:
            logging.debug(f"skipping helm repository '{ansible_chart_repo['url']}' since no ansible "
                          "helm task uses it")
            continue

        logging.debug(f"processing helm repository '{ansible_chart_repo['url']}'")
        try:
            helm_chart_url = f"{ansible_chart_repo['url']}/index.yaml"
            repo_response = requests.get(url=helm_chart_url, verify=verify_ssl)
        except Exception as e:
            logging.error(f"unable to fetch helm repository '{helm_chart_url}'. {str(e)}")
            errors = True
            continue

        if repo_response.status_code != 200:
            logging.error(f"'{helm_chart_url}' returned: {repo_response.status_code}")
            errors = True
            continue

        try:
            repo_charts = yaml.safe_load(repo_response.content)
        except Exception as e:
            logging.error(f"unable to parse '{helm_chart_url}'. {str(e)}")
            errors = True
            continue

        for repo_charts in repo_charts['entries'].items():
            chart_name = repo_charts[0]
            for chart in ansible_helm_charts_matching:
                if chart['name'] != chart_name:
                    continue
                versions = []
                ansible_chart_version = [chart['version'] for chart in ansible_helm_charts_matching if
                                        chart['name'] == chart_name]
                ansible_chart_version = ansible_chart_version[0]
                for repo_chart in repo_charts[1]:
                    if not semver.VersionInfo.isvalid(repo_chart['version'].lstrip('v')):
                        logging.warning(f"helm chart '{repo_chart['name']}' has an invalid "
                                        f"version '{repo_chart['version']}'")
                        continue
                    version = semver.VersionInfo.parse(repo_chart['version'].lstrip('v'))
                    if version.prerelease and not enable_prereleases:
                        logging.debug(f"skipping version '{repo_chart['version']}' of helm chart '{repo_chart['name']}' "
                                    f"because it is a pre-release")
                        continue
                    logging.debug(f"found version '{repo_chart['version']}' of "
                                f"helm chart '{repo_chart['name']}'")
                    versions.extend([repo_chart['version']])

                clean_versions = [version.lstrip('v') for version in versions]
                latest_version = str(max(map(semver.VersionInfo.parse, clean_versions)))

                latest_version = [version for version in versions if latest_version in version]

                if semver.match(latest_version[0].lstrip('v'), f">{ansible_chart_version.lstrip('v')}"):
                    repo_chart = {
                        'name': chart_name,
                        'old_version': ansible_chart_version,
                        'new_version': latest_version[0],
                        'yaml_path': chart['yaml_path']
                    }
                    chart_updates.append(repo_chart)
                    logging.info(f"found update for helm chart '{repo_chart['name']}': "
                                f"'{ansible_chart_version}' to '{latest_version[0]}'")
                    continue
                logging.debug(f"no update found for helm chart '{repo_charts[0]}'. "
                            f"current version in ansible helm task is '{ansible_chart_version}'")


def get_assignee_ids(cli: gitlab.Gitlab, assignees: List[str]) -> List[int]:
    """search assignees with name and get their id

    Args:
        cli (gitlab.Gitlab): gitlab.Gitlab object
        assignees (List[str]): list of assignees with their names

    Returns:
        List[int]: list of assignees with their id's
    """

    assignee_ids = []
    for assignee in assignees:
        try:
            assignee = cli.users.list(search=assignee)
            if not assignee:
                logging.warning("id of '{assignee}' not found")
                continue
            assignee_ids.append(assignee[0].id)
        except Exception as e:
            logging.error(f"cannot get id of assignee '{assignee}'. {e}")

    return assignee_ids


def get_project(cli: gitlab.Gitlab, project_id: int):
    """get gitlab project as object

    Args:
        cli (gitlab.Gitlab): gitlab.Gitlab object
        project_id (int): project id

    Raises:
        TypeError: cli is not of type gitlab.Gitlab
        gitlab.exceptions.GitlabGetError: project not found
        ConnectionError: cannot connect to gitlab project

    Returns:
        gitlab.v4.objects.Project: gitlab project object
    """

    if not isinstance(cli, gitlab.Gitlab):
        raise TypeError(f"parameter 'cli' must be of type 'gitlab.Gitlab', got '{type(cli)}'")

    try:
        project = cli.projects.get(project_id)
    except gitlab.exceptions.GitlabGetError as e:
        raise gitlab.exceptions.GitlabGetError(f"project '{project_id}' not found. {e}")
    except Exception as e:
        raise ConnectionError(f"unable to connect to gitlab. {str(e)}")

    return project


def update_project(project: object,
                   gitlab_file_path: str,
                   repo_file_path: str,
                   chart_name: str,
                   old_version: str,
                   new_version: str,
                   remove_source_branch: bool = False,
                   squash: bool = False,
                   assignee_ids: List[int] = []) -> object:
    """update file in gitlab project

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        gitlab_file_path (str): path to file on gitlab
        repo_file_path (str): path to file inside repo
        chart_name (str): name of chart
        old_version (str): current version of chart
        new_version (str): new version of chart
        remove_source_branch (str, optional):. remove brunch after merge. Defaults to 'False'.
        squash (str, optional):. squash commits after merge. Defaults to 'False'.
        assignee_ids (List[int], optional): list of assignee id's to assign mr. Defaults to [].

    Raises:
        TypeError: project is not of type gitlab.v4.objects.Project
        LookupError: branch could not be created
        Exception: merge request could not be created
        Exception: unable to upload new file content

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: gitlab merge request object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    mergerequest_title = templates.merge_request_title.format(CHART_NAME=chart_name,
                                                              NEW_VERSION=new_version)

    try:
        merge_request = check_merge_requests(project=project,
                                             title=mergerequest_title,
                                             chart_name=chart_name)
    except Exception as e:
        raise LookupError(f"unable check existing merge requests. {str(e)}")

    if merge_request.closed:
        return

    if merge_request.exists:
        return

    description = templates.description.format(
                    FILE_PATH=gitlab_file_path,
                    CHART_NAME=chart_name,
                    OLD_VERSION=old_version,
                    NEW_VERSION=new_version)
    branch_name = templates.branch_name.format(CHART_NAME=chart_name)

    mr = None
    if merge_request.update:
        try:
            mr = get_merge_request_by_name(project=project,
                                           chart_name=chart_name)
            if not mr:
                raise LookupError("merge request not found!")

            mr.title = mergerequest_title
            mr.description = description
            mr.remove_source_branch = remove_source_branch
            mr.squash = squash
            mr.save()
        except Exception as e:
            raise Exception(f"cannot update merge request. {str(e)}")

    if merge_request.missing:
        try:
            create_branch(project=project,
                          branch_name=branch_name)
        except gitlab.exceptions.GitlabCreateError as e:
           logging.debug(f"cannot create branch '{branch_name}'. {str(e.error_message)}")
        except Exception as e:
            raise Exception(f"cannot create branch '{branch_name}'. {str(e)}")

        try:
            mr = create_merge_request(project=project,
                                     branch_name=branch_name,
                                     description=description,
                                     title=mergerequest_title,
                                     remove_source_branch=remove_source_branch,
                                     squash=squash,
                                     assignee_ids=assignee_ids,
                                     labels=["helminator"])
        except Exception as e:
            raise Exception(f"unable to create merge request. {str(e)}")

    try:
        old_chart_version = re.compile(pattern=templates.chart_version.format(VERSION=old_version),
                                       flags=re.IGNORECASE)
        new_chart_version = templates.chart_version.format(VERSION=new_version)
        with open(file=repo_file_path, mode="r+") as f:
            old_content = f.read()
            new_content = re.sub(pattern=old_chart_version,
                                 repl=new_chart_version,
                                 string=old_content)

            update_file(
                project=project,
                branch_name=branch_name,
                commit_msg=mergerequest_title,
                content=new_content,
                path_to_file=gitlab_file_path)
    except Exception as e:
        raise Exception(f"unable to upload file. {str(e)}")

    return mr


def get_merge_request_by_name(project: object,
                              chart_name: str) -> object:
    """get merge request by name

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        chart_name (str): name of chart

    Raises:
        TypeError: project variable is not of type 'gitlab.v4.objects.Project'

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: gitlab merge request object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    mrs = project.mergerequests.list(order_by='updated_at',
                                     state='opened')
    mr_title = re.compile(pattern=pattern.mr_title.format(CHART_NAME=chart_name),
                          flags=re.IGNORECASE)
    for mr in mrs:
        if mr_title.match(mr.title) and "helminator" in mr.labels:
            return mr

    return None


def create_branch(project: object,
                  branch_name: str) -> object:
    """create a branch on gitlab
    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        branch_name (str): name of branch
    Raises:
        TypeError: project variable is not of type 'gitlab.v4.objects.Project'

    Returns:
        gitlab.v4.objects.ProjectBranch: gitlab branch object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    branch = project.branches.create(
        {
            'branch': branch_name,
            'ref': 'master',
        }
    )

    logging.info(f"successfully created branch '{branch_name}'")

    return branch


def check_merge_requests(project: object,
                         title: str,
                         chart_name: str) -> namedtuple:
    """check if a merge request already exists

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        title (str): title of merge request
        chart_name (str): name of chart

    Raises:
        TypeError: project variable is not of type 'gitlab.v4.objects.Project'

    Returns:
        namedtuple: status of merge request
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    mr_title = re.compile(pattern=pattern.mr_title.format(CHART_NAME=chart_name),
                          flags=re.IGNORECASE)
    Status = namedtuple("Status", ["closed", "exists", "update", "missing"])

    mrs = project.mergerequests.list(order_by='updated_at')
    for mr in mrs:
        if "helminator" not in mr.labels:
            continue

        if not mr_title.match(mr.title):
            continue

        if mr.state == "closed" and mr.title == title:
            logging.debug(f"merge request '{title}' was closed")
            return Status(closed=True, exists=False, update=False, missing=False)

        if mr.title == title:
            logging.debug(f"merge request '{title}' already exists")
            return Status(closed=False, exists=True, update=False, missing=False)

        if mr.state == "closed":  # closed mr with 'old' version
            continue

        return Status(closed=False, exists=False, update=True, missing=False)

    return Status(closed=False, exists=False, update=False, missing=True)


def create_merge_request(project: object,
                         title: str,
                         branch_name: str,
                         description: str = None,
                         remove_source_branch: bool = False,
                         squash: bool = False,
                         assignee_ids: List[int] = [],
                         labels: List[str] = []) -> object:
    """create merge request on a gitlab project
    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        title (str): title of branch
        branch_name (str, optional): name of branch. Defaults to 'master'.
        description (str, optional): description of merge request
        remove_source_branch (str, optional):. remove brunch after merge. Defaults to 'False'.
        squash (str, optional):. squash commits after merge. Defaults to 'False'.
        assignee_ids (List[int], optional): assign merge request to persons. Defaults to 'None'.
        labels (List[str]): labels
    Raises:
        TypeError: project variable is not of type 'gitlab.v4.objects.Project'
        ValueError: 'assignee_ids' must be a list of int
        LookupError: branch does not exist

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: gitlab merge request object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    if assignee_ids and not all(isinstance(a, int) for a in assignee_ids):
        raise ValueError("assignee_ids must be a list of int")

    try:
        project.branches.get(branch_name)  # check if branch exists
    except gitlab.exceptions.GitlabGetError:
        raise LookupError(f"branch '{branch_name}' not found. to create a "
                           "merge request, you need a branch!")
    except:
        raise

    mr = {
        'source_branch': branch_name,
        'target_branch': 'master',
        'title': title,
    }

    if description:
        mr['description'] = description

    if labels:
        mr['labels'] = labels

    if remove_source_branch:
        mr['remove_source_branch'] = remove_source_branch

    if squash:
        mr['squash'] = squash

    mr = project.mergerequests.create(mr)
    if assignee_ids:
        mr.todo()
        mr.assignee_ids = assignee_ids
        mr.save()

    logging.info(f"successfully created merge request '{title}'")

    return mr


def update_file(project: object,
                commit_msg: str,
                content: str,
                path_to_file: str,
                branch_name: str = 'master'):
    """update file on a gitlab project
    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        commit_msg (str): commit message
        content (str): file content as string
        path_to_file (str): path to file on the gitlab project
        branch_name (str, optional): [description]. Defaults to 'master'.
    Raises:
        TypeError: project variable is not a type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    commited_file = project.files.get(file_path=path_to_file,
                                      ref=branch_name)

    base64_message = commited_file.content
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    commit_conntent = message_bytes.decode('ascii')

    if content == commit_conntent:
        logging.debug("current commit is up to date")
        return

    payload = {
        "branch": branch_name,
        "commit_message": commit_msg,
        "actions": [
            {
                'action': 'update',
                'file_path': path_to_file,
                'content': content,
            }
        ]
    }

    project.commits.create(payload)
    logging.info(f"successfully update file '{path_to_file}'")


def send_slack(msg, slack_token, slack_channel):
    try:
        slack_client = WebClient(token=slack_token)
        slack_client.chat_postMessage(channel=slack_channel,
                                      text=msg)
    except SlackApiError:
        raise


def main():
    global errors
    try:
        env_vars = check_env_vars()
    except Exception as e:
        sys.stderr.write(f"{str(e)}\n")
        sys.exit(1)

    try:
        setup_logger(loglevel=env_vars.loglevel)
    except Exception as e:
        logging.critical(f"cannot setup logger. {e}")
        sys.exit(1)

    try:
        additional_vars = None
        if env_vars.vars_file:
            if not os.path.exists(env_vars.vars_file):
                raise FileNotFoundError(f"vars file '{env_vars.vars_file}' not found")

            with open(env_vars.vars_file) as stream:
                additional_vars = yaml.safe_load(stream)
    except Exception as e:
        logging.critical(f"unable to process extra vars yaml. {str(e)}")
        sys.exit(1)

    try:
        process_yaml(search_dir=env_vars.search_dir,
                     additional_vars=additional_vars,
                     enable_prereleases=env_vars.enable_prereleases)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    try:
        get_chart_updates(enable_prereleases=env_vars.enable_prereleases,
                          verify_ssl=env_vars.verify_ssl)
    except Exception as e:
        logging.critical(f"unable to process charts. {str(e)}")
        sys.exit(1)

    if env_vars.enable_mergerequests and chart_updates:
        try:
            try:
                cli = gitlab.Gitlab(url=env_vars.gitlab_url,
                                    private_token=env_vars.gitlab_token,
                                    ssl_verify=env_vars.verify_ssl)
            except Exception as e:
                raise ConnectionError(f"unable to connect to gitlab. {str(e)}")

            try:
                if env_vars.assignees:
                    assignee_ids = get_assignee_ids(cli=cli,
                                                    assignees=env_vars.assignees)
            except:
                raise ConnectionError(f"unable to get assignees. {str(e)}")

            try:
                project = get_project(cli=cli,
                                      project_id=env_vars.project_id)
            except Exception as e:
                raise ConnectionError(f"cannot get gitlab project. {str(e)}")

            len_base = len(env_vars.search_dir) + 1
            for chart in chart_updates:
                gitlab_file_path = str(chart['yaml_path'])[len_base:]
                repo_file_path = str(chart['yaml_path'])

                try:
                    mr = update_project(project=project,
                                        gitlab_file_path=gitlab_file_path,
                                        repo_file_path=repo_file_path,
                                        chart_name=chart['name'],
                                        old_version=chart['old_version'],
                                        new_version=chart['new_version'],
                                        remove_source_branch=env_vars.remove_source_branch,
                                        squash=env_vars.squash,
                                        assignee_ids=assignee_ids)
                    if mr:
                        chart['mr_link'] = mr.web_url
                except Exception as e:
                    logging.error(f"cannot update repository. {e}")
        except Exception as e:
            errors = True
            logging.critical(f"unable to update gitlab. {str(e)}")

    if env_vars.slack_token and chart_updates:
        text = [f"The following chart update{'s are' if len(chart_updates) > 1 else ' is'} available:"]
        text.extend([templates.slack_notification.format(CHART_NAME=chart['name'],
                                                         OLD_VERSION=chart['old_version'],
                                                         NEW_VERSION=f"{chart['new_version']}>" if chart.get('mr_link') else chart['new_version'],
                                                         LINK=f"{chart['mr_link']}|" if chart.get('mr_link') else "") for chart in chart_updates])
        text = '\n'.join(text)

        try:
            send_slack(msg=text,
                       slack_token=env_vars.slack_token,
                       slack_channel=env_vars.slack_channel)
        except SlackApiError as e:
            logging.critical(f"unable to send slack notification. {e.response['error']}")
            sys.exit(1)

    sys.exit(1 if errors else 0)  # global error testen


if __name__ == "__main__":
    main()

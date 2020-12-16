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

try:
    import gitlab
    import requests
    import semver
    import yaml
    from gitlab import Gitlab
    from gitlab.exceptions import GitlabCreateError, GitlabGetError, GitlabUpdateError, GitlabUploadError
    from gitlab.v4.objects import Project, ProjectBranch, ProjectCommit, ProjectMergeRequest
    from slack import WebClient
    from slack.errors import SlackApiError
except Exception:
    sys.stderr.write("requirements are not satisfied! see 'requirements.txt'\n")
    sys.exit(1)


__version__ = "2.1.1"

ansible_chart_repos, ansible_helm_charts, chart_updates = [], [], []
errors = False

Pattern = namedtuple("Pattern", ['with_items', 'mr_title',])
pattern = Pattern(
    with_items=re.compile(r"^{{.*\.(\w+) }}"),
    mr_title=r"^(Update {CHART_NAME} chart to )v?(\d+.\d+.\d+).*",
)

helm_task_names = ['community.kubernetes.helm', 'helm']
helm_repository_task_names = ['community.kubernetes.helm_repository', 'helm_repository']

Templates = namedtuple("templates", ['branch_name',
                                     'merge_request_title',
                                     'description',
                                     'chart_version',
                                     'slack_notification',
                                    ]
)
templates = Templates(
    branch_name="helminator/{CHART_NAME}",
    merge_request_title="Update {CHART_NAME} chart to {NEW_VERSION}",
    description="| File | Chart | Change |\n"
                "| :-- | :-- | :-- |\n"
                "{FILE_PATH} | {CHART_NAME} | `{OLD_VERSION}` -> `{NEW_VERSION}`",
    chart_version="chart_version: {VERSION}",
    slack_notification="{LINK_START}{CHART_NAME}{LINK_END}: `{OLD_VERSION}` -&gt; `{NEW_VERSION}`",
)


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

    labels = os.environ.get("HELMINATOR_GITLAB_LABELS")
    labels = [] if labels == "" else ["helminator"] if labels is None else [l.strip() for l in labels.split(",") if l]

    slack_token = os.environ.get("HELMINATOR_SLACK_API_TOKEN")
    slack_channel = os.environ.get("HELMINATOR_SLACK_CHANNEL")

    gitlab_url = os.environ.get("CI_SERVER_URL")
    project_id = os.environ.get("CI_PROJECT_ID")

    if not project_id:
        raise EnvironmentError("environment variable 'CI_PROJECT_ID' not set!")

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
                                       'labels',
                                       'slack_token',
                                       'slack_channel',
                                       'gitlab_url',
                                       'project_id',
                                       ]
    )

    return Env_vars(
        search_dir=search_dir,
        vars_file=vars_file,
        enable_prereleases=enable_prereleases,
        verify_ssl=verify_ssl,
        loglevel=loglevel,
        enable_mergerequests=enable_mergerequests,
        gitlab_token=gitlab_token,
        remove_source_branch=remove_source_branch,
        squash=squash,
        assignees=assignees,
        labels=labels,
        slack_token=slack_token,
        slack_channel=slack_channel,
        gitlab_url=gitlab_url,
        project_id=int(project_id),
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
            logging.error(f"unexpected exception while parsing yaml '{item.absolute}'. {str(e)}")


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

                if additional_vars and isinstance(with_items, str):
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
                logging.warning(
                    f"ansible helm task '{repo_name}/{chart_name}' has an invalid version '{chart_version}'")
                return
            version = semver.VersionInfo.parse(chart_version.lstrip('v'))
            if version.prerelease and not enable_prereleases:
                logging.warning(f"skipping ansible helm task '{repo_name}/{chart_name}' with version "
                                f"'{chart_version}' because it is a pre-release")
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
                    logging.debug("found ansible helm_repository task "
                                  f"'{_item[item_repo_name]}' with url '{_item[item_repo_url]}'")
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
                        logging.warning(
                            f"helm chart '{repo_chart['name']}' has an invalid version '{repo_chart['version']}'")
                        continue
                    version = semver.VersionInfo.parse(repo_chart['version'].lstrip('v'))
                    if version.prerelease and not enable_prereleases:
                        logging.debug(f"skipping version '{repo_chart['version']}' of helm chart "
                                      f"'{repo_chart['name']}' because it is a pre-release")
                        continue
                    logging.debug(f"found version '{repo_chart['version']}' of helm chart '{repo_chart['name']}'")
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


def get_assignee_ids(conn: Gitlab, assignees: List[str]) -> List[int]:
    """search assignees with name and get their id

    Args:
        conn (gitlab.Gitlab): GitLab server connection object
        assignees (List[str]): list of assignees with their names

    Raises:
        TypeError: parameter 'conn' is not of type 'gitlab.Gitlab'

    Returns:
        List[int]: list of assignees with their id's
    """
    if not isinstance(conn, gitlab.Gitlab):
        raise TypeError(f"parameter 'conn' must be of type 'gitlab.Gitlab', got '{type(conn)}'")

    assignee_ids = []
    for assignee in assignees:
        try:
            assignee = conn.users.list(search=assignee)
            if not assignee:
                logging.warning("id of '{assignee}' not found")
                continue
            assignee_ids.append(assignee[0].id)
        except Exception as e:
            logging.error(f"cannot get id of assignee '{assignee}'. {e}")

    return assignee_ids


def get_project(conn: Gitlab, project_id: int) -> Project:
    """get Gitlab project as object

    Args:
        conn (gitlab.Gitlab): Gitlab server connection object
        project_id (int): project id

    Raises:
        TypeError: parameter 'conn' is not of type 'gitlab.Gitlab'
        GitlabGetError: project not found
        ConnectionError: cannot connect to Gitlab project

    Returns:
        gitlab.v4.objects.Project: Gitlab project object
    """

    if not isinstance(conn, gitlab.Gitlab):
        raise TypeError(f"parameter 'conn' must be of type 'gitlab.Gitlab', got '{type(conn)}'")

    try:
        project = conn.projects.get(project_id)
    except GitlabGetError as e:
        raise GitlabGetError(f"project '{project_id}' not found. {e}")
    except Exception as e:
        raise ConnectionError(f"unable to connect to gitlab. {str(e)}")

    return project


def update_project(project: Project,
                   local_file_path: str,
                   gitlab_file_path: str,
                   chart_name: str,
                   old_version: str,
                   new_version: str,
                   remove_source_branch: bool = False,
                   squash: bool = False,
                   assignee_ids: List[int] = [],
                   labels: List[str] = []) -> ProjectMergeRequest:
    """Main function for handling branches, merge requests and version in file.

    - create/update a branch
    - create/update a merge request
    - replace the version in a file and updates the content to a Gitlab repo

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        local_file_path (str): path to the local file
        gitlab_file_path (str): path to file on Gitlab
        chart_name (str): name of chart
        old_version (str): current version of chart
        new_version (str): new version of chart
        remove_source_branch (str, optional):. remove brunch after merge. Defaults to 'False'.
        squash (str, optional):. squash commits after merge. Defaults to 'False'.
        assignee_ids (List[int], optional): list of assignee id's to assign mr. Defaults to [].
        labels (List[str], optional): list of labels to set. Defaults to [].

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
        LookupError: branch could not be created
        GitlabUpdateError: unable to update merge request
        GitlabCreateError: unable to create branch
        GitlabCreateError: unable to create merge request
        GitlabUploadError: unable to upload new file content

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: Gitlab merge request object
    """
    global errors
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    mergerequest_title = templates.merge_request_title.format(CHART_NAME=chart_name,
                                                              NEW_VERSION=new_version)

    try:
        merge_request = eval_merge_requests(project=project,
                                            title=mergerequest_title,
                                            chart_name=chart_name)
    except Exception as e:
        raise LookupError(f"unable check existing merge requests. {str(e)}")

    if merge_request.closed:
        return

    if merge_request.exists:
        return

    description = templates.description.format(FILE_PATH=gitlab_file_path,
                                               CHART_NAME=chart_name,
                                               OLD_VERSION=old_version,
                                               NEW_VERSION=new_version)
    branch_name = templates.branch_name.format(CHART_NAME=chart_name)

    mr = None
    if merge_request.update:
        try:
            mr = get_merge_request_by_title(project=project,
                                            title=pattern.mr_title.format(CHART_NAME=chart_name),
                                            state="opened",
                                            sort="desc")
            if not mr:
                raise LookupError(f"merge request '{chart_name}' not found!")

            mr = mr[0]  # get newest merge request
            if labels:
                mr.labels = labels
            mr.title = mergerequest_title
            mr.description = description
            if remove_source_branch is not None:
                mr.remove_source_branch = str(remove_source_branch).lower() == "true"
            if squash is not None:
                mr.squash = str(squash).lower() == "true"
            mr.save()
        except Exception as e:
            raise GitlabUpdateError(f"cannot update merge request. {str(e)}")

    if merge_request.missing:
        try:
            create_branch(project=project,
                          branch_name=branch_name)
        except GitlabCreateError as e:
           logging.debug(f"cannot create branch '{branch_name}'. {str(e.error_message)}")
        except Exception as e:
            raise GitlabCreateError(f"cannot create branch '{branch_name}'. {str(e)}")

        try:
            mr = create_merge_request(project=project,
                                      branch_name=branch_name,
                                      description=description,
                                      title=mergerequest_title,
                                      remove_source_branch=remove_source_branch,
                                      squash=squash,
                                      assignee_ids=assignee_ids,
                                      labels=labels)
        except Exception as e:
            raise GitlabCreateError(f"unable to create merge request. {str(e)}")

    try:
        old_chart_version = re.compile(pattern=templates.chart_version.format(VERSION=old_version),
                                       flags=re.IGNORECASE)
        new_chart_version = templates.chart_version.format(VERSION=new_version)
        with open(file=local_file_path, mode="r+") as f:
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
        raise GitlabUploadError(f"unable to upload file. {str(e)}")

    return mr


def get_merge_request_by_title(project: Project,
                               title: str,
                               state: str = "all",
                               sort: str = "desc") -> List[ProjectMergeRequest]:
    """return list merge request by matching title (can be regex pattern)

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        title (str): name of chart. Can be regex pattern
        state (str, optional): state of merge requests. Must be one of
                               'all', 'merged', 'opened' or 'closed' Default to 'all'.
        state (str, optional): sort order of merge requests. 'asc' or 'desc'. Default to "desc.

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
        TypeError: parameter 'state' is not 'all', 'merged', 'opened' or 'closed'
        TypeError: parameter 'sort' is not 'asc' or 'desc'

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: list of Gitlab merge request objects
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    if state not in ['all', 'merged', 'opened', 'closed']:
        raise TypeError("parameter 'state' must be 'all', 'merged', 'opened' or 'closed'")

    if sort not in ['asc', 'desc']:
        raise TypeError("parameter 'sort' must be 'asc' or 'desc'")

    mrs = project.mergerequests.list(order_by='updated_at',
                                     state=state,
                                     sort=sort)
    mr_title = re.compile(pattern=title,
                          flags=re.IGNORECASE)
    founds = []
    for mr in mrs:
        if mr_title.match(mr.title):
            founds.append(mr)

    return founds


def create_branch(project: Project,
                  branch_name: str) -> ProjectBranch:
    """create a branch on gitlab

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        branch_name (str): name of branch
    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'

    Returns:
        gitlab.v4.objects.ProjectBranch: Gitlab branch object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    branch = project.branches.create(
        {
            'branch': branch_name,
            'ref': 'master',
        }
    )

    logging.info(f"successfully created branch '{branch_name}'")

    return branch


def eval_merge_requests(project: Project,
                        title: str,
                        chart_name: str) -> namedtuple:
    """evaluate existing mergere request

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        title (str): title of merge request to search
        chart_name (str): name of chart

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'

    Returns:
        namedtuple: Status(closed=bool, exists=bool, update=bool, missing=bool)
                    closed: mr with same version exists and its status is closed
                    exists: mr with same version exists and its status is opened
                    update: mr status is opend but mr has other version
                    missing: none of the above conditions apply
                    Only one of the above status can be true
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    mr_title = re.compile(pattern=pattern.mr_title.format(CHART_NAME=chart_name),
                          flags=re.IGNORECASE)
    Status = namedtuple("Status", ['closed', 'exists', 'update', 'missing'])

    mrs = project.mergerequests.list(order_by='updated_at')
    for mr in mrs:
        if not mr_title.match(mr.title):
            continue

        if mr.state == "closed" and mr.title == title:
            logging.debug(f"merge request '{title}' was closed")
            return Status(closed=True, exists=False, update=False, missing=False)

        if mr.state == "opened" and mr.title == title:
            logging.debug(f"merge request '{title}' already exists")
            return Status(closed=False, exists=True, update=False, missing=False)

        if mr.state == "opened":
            return Status(closed=False, exists=False, update=True, missing=False)

    return Status(closed=False, exists=False, update=False, missing=True)


def create_merge_request(project: Project,
                         title: str,
                         branch_name: str,
                         description: str = None,
                         remove_source_branch: bool = False,
                         squash: bool = False,
                         assignee_ids: List[int] = [],
                         labels: List[str] = []) -> ProjectMergeRequest:
    """create merge request on a Gitlab project

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        title (str): title of branch
        branch_name (str, optional): name of branch. Defaults to 'master'.
        description (str, optional): description of merge request
        remove_source_branch (str, optional):. remove brunch after merge. Defaults to 'False'.
        squash (str, optional):. squash commits after merge. Defaults to 'False'.
        assignee_ids (List[int], optional): assign merge request to persons. Defaults to 'None'.
        labels (List[str]): labels to set

    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
        TypeError: parameter 'assignee_ids' must be a list of int
        TypeError: parameter 'labels' must be a list of strings
        LookupError: branch does not exist

    Returns:
        gitlab.v4.objects.ProjectMergeRequest: Gitlab merge request object
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

    if assignee_ids and not all(isinstance(a, int) for a in assignee_ids):
        raise TypeError("parameter 'assignee_ids' must be a list of int")

    if labels and not all(isinstance(l, str) for l in labels):
        raise TypeError(f"parameter 'labels' must be a list of strings")

    try:
        project.branches.get(branch_name)  # check if branch exists
    except GitlabGetError:
        raise LookupError(f"branch '{branch_name}' not found. to create a merge request, you need a branch!")
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

    if remove_source_branch is not None:
        mr['remove_source_branch'] = str(remove_source_branch).lower() == "true"

    if squash is not None:
        mr['squash'] = str(squash).lower() == "true"

    mr = project.mergerequests.create(mr)
    if assignee_ids:
        mr.todo()
        mr.assignee_ids = assignee_ids
        mr.save()

    logging.info(f"successfully created merge request '{title}'")

    return mr


def update_file(project: Project,
                commit_msg: str,
                content: str,
                path_to_file: str,
                branch_name: str = 'master') -> ProjectCommit:
    """update a file content on a Gitlab project

    Args:
        project (gitlab.v4.objects.Project): Gitlab project object
        commit_msg (str): commit message
        content (str): file content as string
        path_to_file (str): path to file on the Gitlab project
        branch_name (str, optional): [description]. Defaults to 'master'.
    Raises:
        TypeError: parameter 'project' is not of type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError(f"parameter 'project' must be of type 'gitlab.v4.objects.Project', got '{type(project)}'")

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

    commit = project.commits.create(payload)
    logging.info(f"successfully update file '{path_to_file}'")

    return commit


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
                conn = gitlab.Gitlab(url=env_vars.gitlab_url,
                                    private_token=env_vars.gitlab_token,
                                    ssl_verify=env_vars.verify_ssl)
            except Exception as e:
                raise ConnectionError(f"unable to connect to gitlab. {str(e)}")

            try:
                if env_vars.assignees:
                    assignee_ids = get_assignee_ids(conn=conn,
                                                    assignees=env_vars.assignees)
            except Exception as e:
                raise ConnectionError(f"unable to get assignees. {str(e)}")

            try:
                project = get_project(conn=conn,
                                      project_id=env_vars.project_id)
            except Exception as e:
                raise ConnectionError(f"cannot get Gitlab project. {str(e)}")

            # the yaml path in the search_dir does not correspond to the path in the Gitlab repo
            # exmple:
            #  - search_dir: $CI_PROJECT_DIR
            #  - local_file_path: $CI_PROJECT_DIR/tasks/gitlab.yaml
            #  - gitlab_file_path: tasks/gitlab.yaml
            len_base = len(env_vars.search_dir.rstrip("/")) + 1
            for chart in chart_updates:
                local_file_path = str(chart['yaml_path'])
                gitlab_file_path = str(chart['yaml_path'])[len_base:]

                mr = None
                try:
                    mr = update_project(project=project,
                                        local_file_path=local_file_path,
                                        gitlab_file_path=gitlab_file_path,
                                        chart_name=chart['name'],
                                        old_version=chart['old_version'],
                                        new_version=chart['new_version'],
                                        remove_source_branch=env_vars.remove_source_branch,
                                        squash=env_vars.squash,
                                        assignee_ids=assignee_ids,
                                        labels=env_vars.labels)
                except Exception as e:
                    errors = True
                    logging.error(f"cannot update chart '{chart['name']}' ('{gitlab_file_path}'). {e}")
                finally:
                    if mr:
                        chart['mr_link'] = mr.web_url
        except Exception as e:
            errors = True
            logging.critical(e)

    if env_vars.slack_token and chart_updates:
        text = [f"The following chart update{'s are' if len(chart_updates) > 1 else ' is'} available:"]
        for chart in chart_updates:
            mr_link = chart.get('mr_link')
            text.append(templates.slack_notification.format(LINK_START=f"<{mr_link} | " if mr_link else "",
                                                            CHART_NAME=chart['name'],
                                                            LINK_END=">" if mr_link else "",
                                                            OLD_VERSION=chart['old_version'],
                                                            NEW_VERSION=f"{chart['new_version']}" if mr_link else
                                                                          chart['new_version'])
            )
        text = '\n'.join(text)

        try:
            send_slack(msg=text,
                       slack_token=env_vars.slack_token,
                       slack_channel=env_vars.slack_channel)
        except SlackApiError as e:
            logging.critical(f"unable to send slack notification. {e.response['error']}")
            sys.exit(1)

    logging.info("{AMOUNT} chart update{PLURAL} found".format(
        AMOUNT=f"{len(chart_updates)}" if chart_updates else "no",
        PLURAL="s" if len(chart_updates) != 1 else "")
    )
    logging.debug("finish processing")
    sys.exit(1 if errors else 0)  # global error testen


if __name__ == "__main__":
    main()

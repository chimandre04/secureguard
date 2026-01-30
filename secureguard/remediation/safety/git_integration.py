"""Git integration for automated commits of security fixes."""

import subprocess
from typing import List, Optional
from pathlib import Path


class GitIntegration:
    """Handles git operations for automated remediation."""

    def __init__(self, repo_path: Optional[str] = None):
        """Initialize git integration.

        Args:
            repo_path: Path to git repository (defaults to current directory)
        """
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()

        # Check if git is available
        try:
            subprocess.run(
                ["git", "--version"],
                capture_output=True,
                check=True
            )
            self.git_available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.git_available = False
            print("Warning: Git not available - auto-commit disabled")

        # Check if we're in a git repository
        if self.git_available:
            try:
                subprocess.run(
                    ["git", "rev-parse", "--git-dir"],
                    cwd=self.repo_path,
                    capture_output=True,
                    check=True
                )
                self.in_git_repo = True
            except subprocess.CalledProcessError:
                self.in_git_repo = False
                print("Warning: Not in a git repository - auto-commit disabled")

    def create_commit(
        self,
        files: List[str],
        message: str,
        author: Optional[str] = None
    ) -> bool:
        """Create a git commit for the fixed files.

        Args:
            files: List of file paths to commit
            message: Commit message
            author: Optional author string (e.g., "Name <email>")

        Returns:
            True if commit was successful
        """
        if not self.git_available or not self.in_git_repo:
            return False

        try:
            # Stage the files
            for file_path in files:
                subprocess.run(
                    ["git", "add", file_path],
                    cwd=self.repo_path,
                    capture_output=True,
                    check=True
                )

            # Create commit
            cmd = ["git", "commit", "-m", message]

            if author:
                cmd.extend(["--author", author])

            subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                check=True
            )

            return True

        except subprocess.CalledProcessError as e:
            print(f"Git commit failed: {e.stderr.decode() if e.stderr else str(e)}")
            return False

    def create_branch(self, branch_name: str) -> bool:
        """Create a new git branch.

        Args:
            branch_name: Name of the branch to create

        Returns:
            True if branch was created
        """
        if not self.git_available or not self.in_git_repo:
            return False

        try:
            subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=self.repo_path,
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def get_current_branch(self) -> Optional[str]:
        """Get the current git branch name.

        Returns:
            Branch name or None
        """
        if not self.git_available or not self.in_git_repo:
            return None

        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=self.repo_path,
                capture_output=True,
                check=True,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes.

        Returns:
            True if there are uncommitted changes
        """
        if not self.git_available or not self.in_git_repo:
            return False

        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.repo_path,
                capture_output=True,
                check=True,
                text=True
            )
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False

    def get_file_diff(self, file_path: str) -> str:
        """Get git diff for a file.

        Args:
            file_path: Path to file

        Returns:
            Diff output
        """
        if not self.git_available or not self.in_git_repo:
            return ""

        try:
            result = subprocess.run(
                ["git", "diff", file_path],
                cwd=self.repo_path,
                capture_output=True,
                check=True,
                text=True
            )
            return result.stdout
        except subprocess.CalledProcessError:
            return ""

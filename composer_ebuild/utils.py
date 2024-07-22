import subprocess
from typing import List


def get_php_useflags() -> List[str]:
    """
    Get the USE flags for dev-lang/php by calling 'equery --no-color u dev-lang/php'.

    :return: A list of enabled USE flags for dev-lang/php.
    """
    try:
        result = subprocess.run(['equery', '--no-color', 'u', 'dev-lang/php'],
                                capture_output=True, text=True, check=True)
        output = result.stdout.split('\n')

        use_flags = []
        for line in output:
            if line.startswith(' + '):
                flag = line.split()[2]
                use_flags.append(flag)

        return use_flags
    except subprocess.CalledProcessError as e:
        print(f"Error running equery: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error: {e}")
        return []

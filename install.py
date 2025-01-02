import subprocess
import sys
import os
import glob

def find_main_script():
    """
    Automatically finds the main Python script in the project directory.
    Assumes the main script has a '.py' extension and is not this runner script.
    """
    return "app.py"

def install_requirements():
    """
    Installs all the dependencies in the provided list with cross-compatibility checks.
    """
    dependencies = [


        'absl-py==0.15.0', 'aioice==0.9.0', 'aiortc==1.9.0', 'altair', 'arrow==1.2.3',
        'asttokens==2.4.1', 'astunparse==1.6.3', 'attrs==24.3.0', 'av==12.3.0', 'beautifulsoup4==4.12.3',
        'blinker==1.9.0', 'build==1.2.2.post1', 'cachelib==0.13.0', 'cachetools==5.5.0', 'certifi==2024.12.14',
        'cffi==1.17.1', 'charset-normalizer==3.4.1', 'click==8.1.8', 'coolname==2.2.0', 'cryptography==44.0.0',
        'deepface==0.0.93', 'distlib==0.3.9', 'dnspython==2.7.0', 'entrypoints==0.4', 'filelock==3.16.1',
        'fire==0.7.0', 'Flask==3.1.0', 'Flask-Cors==5.0.0', 'Flask-Mail==0.10.0', 'Flask-MySQLdb==2.0.0',
        'Flask-WTF==1.2.2', 'flatbuffers==1.12', 'gast==0.4.0', 'gdown==5.2.0', 'gitdb==4.0.11',
        'GitPython==3.1.43', 'google-auth==2.37.0', 'google-auth-oauthlib==0.4.6', 'google-crc32c==1.6.0',
        'google-pasta==0.2.0', 'grpcio==1.34.1', 'gunicorn==23.0.0', 'h5py==3.1.0', 'idna==3.10',
        'ifaddr==0.2.0', 'importlib_metadata==8.5.0', 'infinity==1.5', 'intervals==0.9.2',
        'itsdangerous==2.2.0', 'Jinja2==3.1.5', 'joblib==1.1.0', 'jsonschema==4.23.0', 'jsonschema-specifications==2024.10.1',
        'keras==2.10.0', 'keras-nightly==2.5.0.dev2021032900', 'Keras-Preprocessing==1.1.2', 'libclang==18.1.1',
        'Markdown==3.7', 'markdown-it-py==3.0.0', 'MarkupSafe==3.0.2', 'mdurl==0.1.2', 'mtcnn==0.1.1',
        'mysqlclient==2.2.6', 'namex==0.0.8', 'nltk==3.9.1', 'numpy==1.23.5', 'oauthlib==3.2.2',
        'opencv-contrib-python==4.5.1.48', 'opencv-python==4.10.0.84', 'opencv-python-headless==4.6.0.66',
        'opt-einsum==3.3.0', 'packaging==24.2', 'pandas==1.4.4', 'pillow==11.0.0', 'pip-review==1.3.0',
        'pip-tools==7.4.1', 'pipdeptree==2.24.0', 'protobuf==3.19.6', 'pyarrow==18.1.0', 'pyasn1==0.6.1',
        'pyasn1_modules==0.4.1', 'pycparser==2.22', 'pydeck==0.9.1', 'pyee==12.1.1', 'Pygments==2.18.0',
        'pylibsrtp==0.10.0', 'Pympler==1.1', 'pyOpenSSL==24.3.0', 'pyproject_hooks==1.2.0', 'PySocks==1.7.1',
        'python-dateutil==2.9.0.post0', 'pytz==2024.2', 'referencing==0.35.1', 'regex==2024.11.6',
        'requests==2.32.3', 'requests-oauthlib==2.0.0', 'retina-face==0.0.17', 'retinaface==1.1.1',
        'rich==13.9.0', 'rpds-py==0.22.3', 'rsa==4.9', 'semver==3.0.2', 'six==1.15.0', 'smmap==5.0.1',
        'soupsieve==2.6', 'streamlit==1.10.0', 'streamlit-webrtc==0.42.0', 'stripe==11.4.1', 'tensorboard==2.10.1',
        'tensorboard-data-server==0.6.1', 'tensorboard-plugin-wit==1.8.1', 'tensorflow==2.14.0',
        'tensorflow-estimator==2.8.0', 'tensorflow-io-gcs-filesystem==0.26.0', 'termcolor==1.1.0',
        'toml==0.10.2', 'tomli==2.2.1', 'toolz==1.0.0', 'tornado==6.4.2', 'tqdm==4.67.1',
        'typing-extensions==4.12.2', 'tzdata==2024.2', 'tzlocal==5.2', 'urllib3==2.3.0', 'validators==0.34.0',
        'Werkzeug==3.1.3', 'wrapt==1.12.1', 'WTForms==3.2.1', 'WTForms-Components==0.11.0', 'zipp==3.21.0'
    ]
    
    for package in dependencies:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except subprocess.CalledProcessError:
            print(f"Failed to install {package}. Moving to next package.")

def run_script_with_dependency_handling(script_name):
    """
    Runs the script with automatic handling of missing dependencies.
    """
    try:
        # Attempt to run the script
        subprocess.run(["python", script_name], check=True)
    except subprocess.CalledProcessError as e:
        if "ModuleNotFoundError" in str(e):
            # Extract the missing module name
            missing_module = str(e).split("'")[1]
            print(f"ModuleNotFoundError: {missing_module} is missing. Attempting to install...")
            # Install the missing module
            subprocess.check_call([sys.executable, "-m", "pip", "install", missing_module])
            print(f"Module '{missing_module}' installed successfully. Re-running the script...")
            # Retry running the script
            run_script_with_dependency_handling(script_name)
        else:
            # For any other errors, raise them
            raise
    except ModuleNotFoundError as e:
        # Handle the ModuleNotFoundError if not caught by CalledProcessError
        missing_module = str(e).split("'")[1]
        print(f"ModuleNotFoundError: {missing_module} is missing. Attempting to install...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", missing_module])
        print(f"Module '{missing_module}' installed successfully. Re-running the script...")
        run_script_with_dependency_handling(script_name)

if __name__ == "__main__":
    try:
        # Install dependencies
        install_requirements()

        # Automatically find and run the main script
        script_name = find_main_script()
        print(f"Running script: {script_name}")
        run_script_with_dependency_handling(script_name)
    except Exception as error:
        print(f"An error occurred: {error}")

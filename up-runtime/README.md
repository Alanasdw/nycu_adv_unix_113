# up-runtime

Docker runtime for the UNIX programming class.

## How to use it

- Clone this repo

- Build the required image `upclass/runtime` using the command:
  ```
  ./build.sh
  ```
  You only need to do this once, unless the files placed in the `debian` folder is modified.

- Create the runtime instance using the command:
  ```
  ./start.sh [password]
  ```
  The script will create a docker container named `up-runtime`. It detects the current user's login ID, user ID, and group ID, and then creates the same user within the docker container using a default password of `password`. To change the default password, provide the desired password as the first argument when running the script. Alternatively, you can log into the docker container using the following command:

  ```
  ssh -p 22222 <your-username>@localhost
  ```

  ***Please note that the script must be run as a regular user.*** Ensure that your environment allows a regular user to run the `docker` command. By default, it works with Docker Desktop on macOS or a Windows terminal with WSL integration. For Linux users, you may need to add the current user to the `docker` group.

  You only need to do this once. The container will automatically start when the docker service is started.

- Stop the runtime
  ```
  docker stop up-runtime
  ```

- Destroy the runtime
  ```
  docker rm up-runtime
  ```
  You may also want to delete the `./home` directory created in the same directory of this repo.

- Destroy the image for the runtime
  ```
  docker rmi upclass/runtime
  ```


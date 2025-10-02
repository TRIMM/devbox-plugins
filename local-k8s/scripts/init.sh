#!/bin/bash

set -e

CURRENT_VERSION="1.5.3"

if [ ! -f project.yaml ]; then
    gum style \
        --foreground "#ffffff" --background "#ff0000" \
        --border double --border-background "#ff0000" \
        --margin "1" --padding "0 0" --width "100" --align center \
        "Error, no project.yaml file found"
    exit 1
fi
config=$(cat project.yaml)
if [[ -f "cluster.yaml" ]]; then
  clusterconfig=$(cat cluster.yaml)
else
  clusterconfig="
metadata:
  name: rancher-desktop"
fi

# Below script is used to authenticate with GitLab using NodeJS
gitlab_auth=$(cat <<'EOF'

const os = require('os');
const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const https = require('https');
const crypto = require('crypto');
const port = 8063;

const GITLAB_HOSTNAME = process.env.GITLAB_HOST;
const GITLAB_URL = `https://${GITLAB_HOSTNAME}`;
const CLIENT_ID = process.env.GITLAB_CLIENT_ID;
const REDIRECT_URI = `http://localhost:${port}/callback`;
const AUTH_URL = `${GITLAB_URL}/oauth/authorize`;
const TOKEN_URL = `${GITLAB_URL}/oauth/token`;
const SCOPE = "read_api%20write_repository%20read_registry";
const TOKEN_DIR = path.join(os.homedir(), '.trimm-platform');
const TOKEN_FILE = path.join(TOKEN_DIR, "tokens.json");

// PKCE Helper Functions
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(codeVerifier) {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
}

// Function to request a new access token using the refresh token
function refreshAccessToken() {
  const tokenData = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
  const refreshToken = tokenData.refresh_token;

  const postData = new url.URLSearchParams({
    client_id: CLIENT_ID,
    refresh_token: refreshToken,
    grant_type: 'refresh_token'
  }).toString();

  const options = {
    hostname: GITLAB_HOSTNAME,
    path: '/oauth/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': postData.length
    }
  };

  const req = https.request(options, res => {
    let data = '';

    res.on('data', chunk => {
      data += chunk;
    });

    res.on('end', () => {
      if (res.statusCode === 200) {
        const tokenResponse = JSON.parse(data);
        fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokenResponse, null, 2));
        console.log("Access token refreshed:", tokenResponse.access_token);
      } else {
        console.error("Failed to refresh access token:", data);
        process.exit(1);
      }
    });
  });

  req.on('error', e => {
    console.error("Failed to refresh access token:", e);
    process.exit(1);
  });

  req.write(postData);
  req.end();
}

// Function to open the default browser
function openBrowser(url) {
  const start = (process.platform == 'darwin' ? 'open' : process.platform == 'win32' ? 'start' : 'xdg-open');
  exec(`${start} "${url}"`);
}

// Function to start the local server and capture the authorization code
function startLocalServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const queryObject = url.parse(req.url, true).query;
      const code = queryObject.code;

      if (code) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><p>You can close this window now.</p></body></html>');
        resolve(code);
        server.close();
      } else {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><p>Authorization code not found.</p></body></html>');
      }
    });

    server.listen(port, err => {
      if (err) {
        reject(err);
      } else {
        console.log(`Server is listening on port ${port}`);
      }
    });
  });
}

// Function to exchange authorization code for access token
function exchangeCodeForToken(code, codeVerifier) {
  return new Promise((resolve, reject) => {
    const postData = new url.URLSearchParams({
      client_id: CLIENT_ID,
      code,
      grant_type: 'authorization_code',
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier
    }).toString();

    const options = {
      hostname: GITLAB_HOSTNAME,
      path: '/oauth/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': postData.length
      }
    };

    const req = https.request(options, res => {
      let data = '';

      res.on('data', chunk => {
        data += chunk;
      });

      res.on('end', () => {
        if (res.statusCode === 200) {
          const tokenResponse = JSON.parse(data);
          fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokenResponse, null, 2));
          console.log("Access token obtained:", tokenResponse.access_token);
          resolve();
        } else {
          console.error("Failed to obtain access token:", data);
          reject(new Error('Failed to obtain access token'));
        }
      });
    });

    req.on('error', e => {
      console.error("Failed to obtain access token:", e);
      reject(e);
    });

    req.write(postData);
    req.end();
  });
}

// Main function to handle the OAuth flow
async function main() {
  if (!fs.existsSync(TOKEN_DIR)) {
    // Create the directory
    fs.mkdirSync(TOKEN_DIR);
    console.log(`Directory ${TOKEN_DIR} created successfully.`);
  }
  if (fs.existsSync(TOKEN_FILE)) {
    const tokenData = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    const accessToken = tokenData.access_token;

    const options = {
      hostname: GITLAB_HOSTNAME,
      path: '/api/v4/user',
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    };

    const req = https.request(options, res => {
      let data = '';

      res.on('data', chunk => {
        data += chunk;
      });

      res.on('end', () => {
        if (res.statusCode === 200) {
          const userData = JSON.parse(data);
          console.log("Using stored access token:", accessToken);
          console.log("Authenticated as:", userData.username);
        } else if (res.statusCode === 401) {
          console.log("Access token expired, refreshing...");
          refreshAccessToken();
        } else {
          console.error("Failed to verify access token:", data);
          process.exit(1);
        }
      });
    });

    req.on('error', e => {
      console.error("Failed to verify access token:", e);
      process.exit(1);
    });

    req.end();
  } else {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const authUrl = `${AUTH_URL}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=${SCOPE}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    console.log("Please authorize the application by visiting the following URL:");
    console.log(authUrl);

    openBrowser(authUrl);
    console.log("Starting local server to capture the authorization code...");
    const code = await startLocalServer();

    if (!code) {
      console.error("Failed to capture authorization code.");
      process.exit(1);
    }

    console.log("Authorization code received:", code);
    await exchangeCodeForToken(code, codeVerifier);
  }
}

main();

EOF
)

refresh_gitlab () {
  clear; header

  authorize_gitlab

  clear; menu
}

authorize_gitlab () {
  set +e

  echo "Now we will authenticate with the TRIMM Platform GitLab application"
  echo "$gitlab_auth" | node -

  sleep 1

  set -e
}

setup_modules () {
  if [ -n "$(echo "$config" | yq ".modules[].name")" ]; then
    if [ "$(echo "$config" | yq ".modules | length")" -eq 1 ]; then
      ANSWER=$(gum choose --header "Should I install the $(echo "$config" | yq ".modules[0].name") module?" "Yes" "No")
      echo $ANSWER
      if [ "$ANSWER" == "Yes" ]; then
        MODULES=$(echo "$config" | yq ".modules[0].name")
      fi
    else
      MODULES=$(gum choose --header "Which $(gum style --foreground 212 "modules") do you need?" --cursor-prefix "[ ] " --unselected-prefix "[ ] " --selected-prefix "[✓] " --no-limit $(echo "$config" | yq ".modules[].name"))
    fi

    clear; header; echo "One moment, please."
    token=$(yq -r .access_token $HOME/.trimm-platform/tokens.json)

    # Loop through each module name
    if [ -n "$MODULES" ]; then
      while IFS= read -r module_name; do
        # Get the repository for the current module name
        repo=$(echo "$config" | yq '.modules[] | select(.name == "'"${module_name}"'") | .repo')

        module_directory="modules/$module_name"

        # Check if directory already exists
        if [ -d "$module_directory" ]; then
            echo "Directory $module_directory already exists. Reverting to git pull."
            gum spin -s line --title "Pulling $module_name..." -- git -C "./$module_directory" pull origin
            sleep 1;
        else
            gum spin -s line --title "Cloning $module_name..." -- git clone "https://oauth2:$token@gitlab.trimm.nl/$repo.git" "$module_directory"
            git -C "./$module_directory" remote set-url origin "git@gitlab.trimm.nl:$repo.git"
        fi
      done <<< "$MODULES"
    fi
  fi

  echo "Done"; sleep 1;
}

setup_frontends () {
  if [ -n "$(echo "$config" | yq ".frontends[].name")" ]; then
    if [ "$(echo "$config" | yq ".frontends | length")" -eq 1 ]; then
      ANSWER=$(gum choose --header "Should I install the $(echo "$config" | yq ".frontends[0].name") frontend?" "Yes" "No")
      echo $ANSWER
      if [ "$ANSWER" == "Yes" ]; then
        FRONTENDS=$(echo "$config" | yq ".frontends[0].name")
      fi
    else
      FRONTENDS=$(gum choose --header "Which $(gum style --foreground 212 "frontends") do you need?" --cursor-prefix "[ ] " --unselected-prefix "[ ] " --selected-prefix "[✓] " --no-limit $(echo "$config" | yq ".frontends[].name"))
    fi

    clear; header; echo "One moment, please."
    token=$(yq -r .access_token $HOME/.trimm-platform/tokens.json)

    # Loop through each frontend name
    if [ -n "$FRONTENDS" ]; then
      while IFS= read -r frontend_name; do
        # Get the repository for the current frontend name
        repo=$(echo "$config" | yq '.frontends[] | select(.name == "'"${frontend_name}"'") | .repo')

        frontend_directory="frontends/$frontend_name"

        # Check if directory already exists
        if [ -d "$frontend_directory" ]; then
            echo "Directory $frontend_directory already exists. Reverting to git pull."
            gum spin -s line --title "Pulling $frontend_name..." -- git -C "./$frontend_directory" pull origin
            sleep 1;
        else
            gum spin -s line --title "Cloning $frontend_name..." -- git clone "https://oauth2:$token@gitlab.trimm.nl/$repo.git" "$frontend_directory"
            git -C "./$frontend_directory" remote set-url origin "git@gitlab.trimm.nl:$repo.git"
        fi
      done <<< "$FRONTENDS"
    fi
  fi

  echo "Done"; sleep 1;
}

setup_services () {
  set +e

  if [ -n "$(echo "$config" | yq ".services[].name")" ]; then
    if [ "$(echo "$config" | yq ".services | length")" -eq 1 ]; then
      ANSWER=$(gum choose --header "Should I install the $(echo "$config" | yq ".services[0].name") service?" "Yes" "No")
      echo $ANSWER
      if [ "$ANSWER" == "Yes" ]; then
        SERVICES=$(echo "$config" | yq ".services[0].name")
      fi
    else
      SERVICES=$(gum choose --header "Which $(gum style --foreground 212 "services") do you need?" --cursor-prefix "[ ] " --unselected-prefix "[ ] " --selected-prefix "[✓] " --no-limit $(echo "$config" | yq ".services[].name"))
    fi

    clear; header; echo "One moment, please."
    token=$(yq -r .access_token $HOME/.trimm-platform/tokens.json)

    # Loop through each service name
    if [ -n "$SERVICES" ]; then
      while IFS= read -r service_name; do
        # Get the repository for the current service name
        repo=$(echo "$config" | yq '.services[] | select(.name == "'"${service_name}"'") | .repo')

        project_directory="services/$service_name"

        # Check if directory already exists
        if [ -d "$project_directory" ]; then
            echo "Directory $project_directory already exists. Reverting to git pull."
            gum spin -s line --title "Pulling $service_name..." -- git -C "./$project_directory" pull origin
            sleep 1;
        else
            gum spin -s line --title "Cloning $service_name..." -- git clone "https://oauth2:$token@gitlab.trimm.nl/$repo.git" "$project_directory"
            git -C "./$project_directory" remote set-url origin "git@gitlab.trimm.nl:$repo.git"
        fi
      done <<< "$SERVICES"
    fi
  fi

  echo "Done"; sleep 1;
}

setup_manifests () {
  if [ "$(echo "$config" | yq "has(\"manifests\")")" = "true" ]; then
    ANSWER=$(gum choose --header "Should clone the manifests repositories?" "No" "Yes")
    echo $ANSWER
    if [ "$ANSWER" == "Yes" ]; then
      token=$(yq -r .access_token $HOME/.trimm-platform/tokens.json)
      if [ -n "$(echo "$config" | yq ".manifests.project")" ]; then
        repo=technology/platform-projects/$(echo "$config" | yq ".manifests.project")
        project_directory="project-manifests"
        # Check if directory already exists
        if [ -d "$project_directory" ]; then
            echo "Directory $project_directory already exists. Reverting to git pull."
            gum spin -s line --title "Pulling $project_directory..." -- git -C "./$project_directory" pull origin
            sleep 1;
        else
            gum spin -s line --title "Cloning $project_directory..." -- git clone "https://oauth2:$token@gitlab.trimm.nl/$repo.git" "$project_directory"
            git -C "./$project_directory" remote set-url origin "git@gitlab.trimm.nl:$repo.git"
        fi
      fi

      if [ -n "$(echo "$config" | yq ".manifests.platform")" ]; then
        repo=$(echo "$config" | yq ".manifests.platform")
        project_directory="platform-manifests"
        # Check if directory already exists
        if [ -d "$project_directory" ]; then
            echo "Directory $project_directory already exists. Reverting to git pull."
            gum spin -s line --title "Pulling $project_directory..." -- git -C "./$project_directory" pull origin
            sleep 1;
        else
            gum spin -s line --title "Cloning $project_directory..." -- git clone "https://oauth2:$token@gitlab.trimm.nl/$repo.git" "$project_directory"
            git -C "./$project_directory" remote set-url origin "git@gitlab.trimm.nl:$repo.git"
        fi
      fi
    fi
  else
    echo "No manifests found in project.yaml, skipping project/platform manifests repositories"
  fi

  echo "Done"; sleep 1;
}

setup_dotenv () {
  if [ ! -f ".env" ]; then
    cp ".env.example" ".env"
    echo "Copied .env.example to .env"
    sleep 1
  fi
}

setup_pullsecrets () {
  echo "Now we will setup your pull secrets, I'll try to copy it from your docker store"

  CREDS=$(gum spin --spinner line --show-output --title "Checking secret store" -- echo "registry.trimm.nl" | docker-credential-osxkeychain get)
  if [ -n "$CREDS" ]; then
      REGISTRY_USER=$(echo "$CREDS" | yq ".Username")
      REGISTRY_PASSWORD=$(echo "$CREDS" | yq ".Secret")
      sed -i "s/^REGISTRY_USER=.*/REGISTRY_USER=$REGISTRY_USER/" ".env"
      sed -i "s/^REGISTRY_PASSWORD=.*/REGISTRY_PASSWORD=$REGISTRY_PASSWORD/" ".env"
      echo "Done"
      sleep 1
  else
      echo "Failure, please add your token to .env manually"
      sleep 3
  fi
}

process_secrets () {
  echo "Now we will setup your local secrets, I'll fetch them from the Platform Vault"

  local has_error=false
  while IFS= read -r item; do
    if grep -q "$item" .env; then
      gum style \
                  --foreground "#ffffff" --background "#ff0000" \
                  --border double --border-background "#ff0000" \
                  --margin "1" --padding "0 0" --width "100" --align center \
                 "Warning: The .env file already contains the $item, delete it and rerun the script."
      has_error=true
    fi
  done < <(echo "$config" | yq '.secrets[].env')

  if [ "$has_error" = true ]; then
    echo "Aborted adding secrets due to preexisting values, either remove all the values or add them manually (see project.yaml:secrets)."
    read -n 1 -s -r -p "Press any key to continue..."
    return;
  fi

  set +e;
  while :
    do
      bao token lookup 2>&1 | grep "permission denied" > /dev/null
      if [[ $? -eq 0 ]]; then
        gum style \
          --foreground "#ffffff" --background "#0d709a" \
          --border double --border-background "#0d709a" \
          --margin "1" --padding "0 0" --width "100" --align center \
          "Note: Login to Vault, using SSO."

        gum spin --spinner line --title "Logging in to TRIMM Platform Vault" -- bao login -method=oidc
      else
        echo "Authenticated to TRIMM Platform Vault"

        break
      fi
      sleep 1
    done
  set -e

  num_secrets=$(echo "$config" | yq '.secrets | length')

  echo "Count: $num_secrets"
  set +e
  for i in $(seq 0 $(($num_secrets - 1))); do
      path=$(echo "$config" | yq ".secrets[$i].path")
      field=$(echo "$config" | yq ".secrets[$i].field")
      env=$(echo "$config" | yq ".secrets[$i].env")

      SECRET=$(bao kv get -field=$field "$path")
      # Check if the secret is not empty
      if [ -z "$SECRET" ]; then
        gum style \
                  --foreground "#ffffff" --background "#ff0000" \
                  --border double --border-background "#ff0000" \
                  --margin "1" --padding "0 0" --width "100" --align center \
                 "Warning: Secret for $env is empty or not found." \
                 "(Vault path $path:$field)" \
                 "You probably don't have the correct permissions..." \
                 "Have the correct role assigned to your user and run Discard from the menu"
        read -n 1 -s -r -p "Press any key to continue..."
        return 0
      fi
      printf '%s\n' "$env=$SECRET" >> .env

      echo "Added $env (value from $path.$field) value to .env"
    done

  sleep 3; clear
}

setup_cluster () {
  clustername=$(echo "$clusterconfig" | yq ".metadata.name")
  name=$(echo "$clusterconfig" | yq ".metadata.name")
  if k3d cluster list | grep -q "^$name"; then
    echo "Cluster $name already exists, skipping creation"
    return
  fi

  if [[ $clustername == "rancher-desktop" ]]; then
    return
  fi

  k3d cluster create --config ./cluster.yaml
}

setup () {
  clear; header

  setup_cluster

  clear; header

  authorize_gitlab

  clear; header

  setup_modules

  clear; header

  setup_frontends

  clear; header

  setup_services

  clear; header

  setup_manifests

  clear; header

  setup_dotenv
  setup_pullsecrets

  clear; header;

  if [ "$(echo "$config" | yq ".secrets | length")" -gt 0 ]; then
    echo "Processing secrets"
    process_secrets
  else
    echo "No secrets found, continuing..."
  fi

  clear; menu
}

update () {
  deploys=`kubectl get deployments -o name`
  for deploy in $deploys; do
    gum spin -s monkey --title "Rolling out $deploy to force image updates" -- kubectl rollout restart $deploy && kubectl rollout status $deploy
  done

  clear; menu
}

run () {
  clustername=$(echo "$clusterconfig" | yq ".metadata.name")
  if [[ $clustername != "rancher-desktop" ]]; then
    k3d cluster start $clustername
    CONTEXT=$(k3d kubeconfig get $clustername | yq ".current-context")
    kubectl config use-context $CONTEXT
  fi

  if [[ $(kubectl config current-context) != *"$clustername"* ]]; then
    echo "Your current kubernetes context is set to $(gum style --foreground "#ff005f" $(kubectl config current-context))"
    if gum confirm "Are you sure you want to deploy the project to $(gum style --foreground "#ff005f" $(kubectl config current-context))?" ; then
      echo "Acknowledged"
    else
      CONTEXT=$(gum choose $(kubectl config get-contexts -o name))
      kubectl config use-context $CONTEXT;
      echo "Current context set to $(gum style --foreground "#ff005f" $(kubectl config current-context))"
    fi
  fi

  echo "Now I will deploy the project to $(gum style --foreground "#ff005f" $(kubectl config current-context))"

  set +e

  authorize_gitlab

  set -e
  OLD_CREDENTIAL_HELPER=$(git config --global credential.helper)
  set +e
  git config --global credential.helper ""
  git config --global credential.https://gitlab.trimm.nl.helper '!f() { sleep 1; echo "username=oauth2"; echo "password=$(yq -r .access_token $HOME/.trimm-platform/tokens.json)"; }; f'
  git config --global credential.https://gitlab.trimm.nl.username oauth2

  devspace use namespace $(echo "$config" | yq ".namespace")
  devspace dev
  devspace_exit_code=$?


  echo "Exiting dev mode, returning to menu"
  git config --global --unset credential.https://gitlab.trimm.nl.helper
  git config --global --unset credential.https://gitlab.trimm.nl.username

  if [ -n "$OLD_CREDENTIAL_HELPER" ]; then
      git config --global credential.helper "$OLD_CREDENTIAL_HELPER"
  fi
  sleep 2
  if [ $devspace_exit_code -eq 0 ]; then
    clear
  fi

  set -e
  menu
}

discard () {
  set +e

  gum spin --show-output -s monkey --title "Removing vault token" -- bao token revoke -self;
  gum spin --show-output -s monkey --title "Removing cluster" -- k3d cluster delete $(echo "$clusterconfig" | yq ".metadata.name");
  gum spin --show-output -s monkey --title "Removing devspace caches/state" -- rm -rf .devspace;

  set -e

  echo "Success, you now have to run the Setup/update task again!"
  read -n 1 -s -r -p "Press any key to continue..."

  clear; menu
}

enter () {
  set +e
  devspace enter
  set -e
  clear; menu
}

header () {
    gum style \
          --foreground "#ffffff" --background "#0d709a" \
          --border double --border-background "#0d709a" \
          --margin "1" --padding "1 2" --width "100" --align center \
          "$(gum style --bold "TRIMM Platform (v$CURRENT_VERSION)")" "Magnolia development" "$(gum style --bold --foreground "#ff005f"--bold "$(echo "$config" | yq '.title') project")"
}

menu () {
  header

  SHELL="Shell         - work in a running devspace container";
  SETUP="Setup/update  - clones dependencies, setup cluster & secrets";
  RUN="Run/develop   - runs devspace prepare and devspace dev";
  STOP="Stop/pause    - pause a complete environment";
  REFRESH="Refresh       - updates GitLab token";
  UPDATE="Update        - pulls latest images";
  DISCARD="Discard       - remove token & containers";
  EXIT="Exit          - return to nix shell";
  ACTIONS=$(gum choose "$RUN" "$STOP" "$SHELL" "$SETUP" "$UPDATE" "$REFRESH" "$DISCARD" "$EXIT")

  grep -q "$SHELL"   <<< "$ACTIONS" && enter
  grep -q "$SETUP"   <<< "$ACTIONS" && setup
  grep -q "$RUN"     <<< "$ACTIONS" && run
  grep -q "$UPDATE"  <<< "$ACTIONS" && update
  grep -q "$REFRESH" <<< "$ACTIONS" && refresh_gitlab
  grep -q "$STOP"    <<< "$ACTIONS" && gum spin -s monkey --title "Stopping k3d cluster" -- k3d cluster stop $(echo "$clusterconfig" | yq ".metadata.name")
  grep -q "$DISCARD" <<< "$ACTIONS" && discard
}

refresh_gitlab
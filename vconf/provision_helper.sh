# wrapper for a package installation pipeline
# with all the necessary checks and outputs
install_package() {
  inst_verif=$1
  package_name=${*: -2:1}
  inst_cmds=${*: -1:1}
  if is_installed $inst_verif; then
    echo " >> ${package_name^^} HAS BEEN ALREADY INSTALLED, EXITING ..."
  else
    echo " >> INSTALLING ${package_name^^} ..."
    export DEBIAN_FRONTEND=noninteractive

    # running actual installation process
    # passed as a second parameter
    eval $inst_cmds > /dev/null 2>&1
    print_installation_status
  fi
}

# check a presence of a passed in command
# returns 0 if check was successful
# returns 1 in other cases
is_installed() {
  eval $inst_verif > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

print_installation_status() {
  if [ $? -eq 0 ]; then
    echo "INSTALL STATUS: OK"
  else
    echo "INSTALL STATUS: FAILED!"
  fi
}

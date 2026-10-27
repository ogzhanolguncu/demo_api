FROM registry.depot.dev/zsh9cdm2c3:proj_Rn7qwG8WE-d_KxUcGy9lU

  # Prints the victim's files in the build log, as proof the pull worked
  RUN ls -la / /app 2>/dev/null || true

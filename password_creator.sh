#!/bin/bash

# Check if a file is provided
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <keys_file>"
  exit 1
fi

# Set the maximum number of keys per combination (customizable)
max_keys=5   # Maximum number of keys in a combination
min_length=12  # Minimum length of the final results to print (customizable)

# Read the file and store keys in an array
keys_file="$1"
if [ ! -f "$keys_file" ]; then
  echo "File not found: $keys_file"
  exit 1
fi

keys=()
while IFS= read -r line; do
  keys+=("$line")
  # Add an additional string with flipped case for the first character
  first_char="${line:0:1}"
  rest="${line:1}"
  if [[ "$first_char" =~ [a-z] ]]; then
    # Lowercase to uppercase
    keys+=("$(tr '[:lower:]' '[:upper:]' <<< "$first_char")$rest")
  elif [[ "$first_char" =~ [A-Z] ]]; then
    # Uppercase to lowercase
    keys+=("$(tr '[:upper:]' '[:lower:]' <<< "$first_char")$rest")
  fi
done < "$keys_file"

# Function to validate password requirements
validate_combination() {
  local combination="$1"
  
  # Ensure the combination includes:
  # - At least one lowercase letter
  # - At least one uppercase letter
  # - At least one special character
  # - At least one number
  if [[ "$combination" =~ [a-z] ]] && [[ "$combination" =~ [A-Z] ]] && \
     [[ "$combination" =~ [^a-zA-Z0-9] ]] && [[ "$combination" =~ [0-9] ]]; then
    return 0 # Valid combination
  else
    return 1 # Invalid combination
  fi
}

# Function to generate combinations
generate_combinations() {
  local combination="$1"
  local used_keys="$2" # Count of keys already used in the combination
  local remaining=("${@:3}")

  # Validate and print the combination if it meets requirements
  if [ "${#combination}" -ge "$min_length" ] && validate_combination "$combination"; then
    echo "$combination"
  fi

  # Stop if the combination has reached the maximum allowed number of keys
  if [ "$used_keys" -ge "$max_keys" ]; then
    return
  fi

  # Add each remaining key to the combination and recurse
  for key in "${remaining[@]}"; do
    # Skip keys already in the current combination
    if [[ "$combination" == *"$key"* ]]; then
      continue
    fi
    generate_combinations "${combination}${key}" $((used_keys + 1)) "${remaining[@]}"
  done
}

# Generate all combinations starting with each key
for key in "${keys[@]}"; do
  remaining=("${keys[@]/$key/}") # Remove the current key from the remaining keys
  generate_combinations "$key" 1 "${remaining[@]}"
done

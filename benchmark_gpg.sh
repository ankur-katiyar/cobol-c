#!/bin/bash

# Check if the number of iterations is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <number_of_iterations>"
    exit 1
fi

# Number of iterations
iterations=$1

# Function to generate a random string of a given length
generate_random_string() {
    local length=$1
    tr -dc A-Za-z0-9 </dev/urandom | head -c ${length}
}

# Executable to be called
executable="./PTPCRYPG " # Replace with your actual executable name

# Length of the random string
string_length=10

# Total time accumulator
total_time=0

# Loop for the number of iterations
for (( i=1; i<=iterations; i++ ))
do
    # Generate a random string
    random_string=$(generate_random_string $string_length)

    # Measure the time taken to execute the command
    start_time=$(date +%s%N)
    $executable "$random_string"
    end_time=$(date +%s%N)

    # Calculate the duration in nanoseconds
    duration=$((end_time - start_time))

    # Accumulate the total time
    total_time=$((total_time + duration))

    echo "Iteration $i: Input='$random_string', Time=$((duration / 1000000)) ms"
done

# Calculate the average time in milliseconds
average_time=$((total_time / iterations / 1000000))

# Output the average time
echo "Average time per call: $average_time ms"

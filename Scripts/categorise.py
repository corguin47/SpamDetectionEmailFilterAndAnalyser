import os
import shutil

# Paths - edit if needed
source_folder = "20050311_spam_2"
destination_root = "CategorisedSpamMail"
input_file = "categorized_results.txt"  # Your text file name here

def main():
    current_category = None
    files_by_category = {}

    # Parse the input file
    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Detect category line
            if line.endswith("emails):"):
                current_category = line.split(" (")[0].strip()
                files_by_category[current_category] = []
            elif line.startswith("- ") or line.startswith("  - "):
                # Extract filename (strip the leading - and spaces)
                filename = line.lstrip("- ").strip()
                if current_category is not None:
                    files_by_category[current_category].append(filename)

    # Add Uncategorized folder if not present
    if "Uncategorized" not in files_by_category:
        files_by_category["Uncategorized"] = []

    # Move files
    for category, filenames in files_by_category.items():
        dest_folder = os.path.join(destination_root, category)
        os.makedirs(dest_folder, exist_ok=True)
        print(f"Processing category '{category}' with {len(filenames)} files...")

        for filename in filenames:
            src_path = os.path.join(source_folder, filename)
            dst_path = os.path.join(dest_folder, filename)

            if os.path.exists(src_path):
                shutil.move(src_path, dst_path)
            else:
                print(f"WARNING: File not found: {src_path}")

    print("Categorisation complete.")

if __name__ == "__main__":
    main()

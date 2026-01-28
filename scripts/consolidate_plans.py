
import os
import re
import shutil

# Directory containing the PLAN documents
DOCS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../app/Documentation'))
OUTPUT_FILE = os.path.join(DOCS_DIR, 'PLAN_history.md')
ARCHIVE_DIR = os.path.join(DOCS_DIR, 'archive')

def natural_sort_key(s):
    """
    Key function for natural sorting.
    e.g., "PLAN_Phase2.md" < "PLAN_Phase10.md"
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split('([0-9]+)', s)]

def main():
    if not os.path.exists(DOCS_DIR):
        print(f"Error: Documentation directory not found at {DOCS_DIR}")
        return

    # 1. List all files matching PLAN*
    files = [f for f in os.listdir(DOCS_DIR) 
             if f.startswith('PLAN') and f.endswith('.md') and f != 'PLAN_history.md']
    
    # 2. Sort naturally
    files.sort(key=natural_sort_key)

    if not files:
        print("No PLAN documents found to consolidate.")
        return

    print(f"Found {len(files)} PLAN documents.")

    # 3. Consolidate content
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as outfile:
            for filename in files:
                filepath = os.path.join(DOCS_DIR, filename)
                print(f"Processing {filename}...")
                
                # Add header
                outfile.write(f"# {filename}\n\n")
                
                # Add content
                with open(filepath, 'r', encoding='utf-8') as infile:
                    outfile.write(infile.read())
                
                # Add separator
                outfile.write("\n\n")
        
        print(f"Successfully created {OUTPUT_FILE}")

    except Exception as e:
        print(f"Error during consolidation: {e}")
        return

    # 4. Create archive directory
    if not os.path.exists(ARCHIVE_DIR):
        os.makedirs(ARCHIVE_DIR)
        print(f"Created archive directory at {ARCHIVE_DIR}")

    # 5. Move files to archive
    for filename in files:
        src = os.path.join(DOCS_DIR, filename)
        dst = os.path.join(ARCHIVE_DIR, filename)
        try:
            shutil.move(src, dst)
            print(f"Archived {filename}")
        except Exception as e:
            print(f"Error archiving {filename}: {e}")

    print("Consolidation and archiving complete.")

if __name__ == "__main__":
    main()

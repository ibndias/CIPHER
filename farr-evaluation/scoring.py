import os
import json
import csv
import sys
from tabulate import tabulate
import plotext as plt

def load_scores(resultdir):
    model_scores = {}
    for root, dirs, files in os.walk(resultdir):
        for dir in dirs:
            for file in os.listdir(os.path.join(root, dir)):
                if file.endswith(".json"):
                    fullpath = os.path.join(root, dir, file)
                    with open(fullpath, "r") as f:
                        data = json.load(f)
                        model_name = file[16:-18]
                        if model_name not in model_scores:
                            model_scores[model_name] = {}
                        model_scores[model_name][dir] = data['final_score']
    return model_scores

def generate_table_data(model_scores):
    machine_names = sorted({machine for scores in model_scores.values() for machine in scores.keys()})
    table_data = []
    for model_name, scores in sorted(model_scores.items()):
        row = [model_name]
        total_score = 0
        valid_scores_count = 0
        for machine_name in machine_names:
            score = scores.get(machine_name)
            if score is not None:
                row.append(score)
                total_score += score
                valid_scores_count += 1
            else:
                row.append("-")
        average_score = total_score / valid_scores_count if valid_scores_count > 0 else "-"
        row.append(average_score)
        table_data.append(row)
    return table_data, machine_names

def save_markdown_table(table_data, machine_names, evaldir, output_dir="result"):
    markdown_table = tabulate(table_data, headers=["Model"] + list(machine_names) + ["Average"], tablefmt="github", stralign="right")
    os.makedirs(output_dir, exist_ok=True)
    markdown_file_path = os.path.join(output_dir, f"{evaldir}-scores.md")
    with open(markdown_file_path, "w") as markdown_file:
        markdown_file.write(markdown_table)
    print("Markdown file saved as:", markdown_file_path)

def save_csv(table_data, machine_names, evaldir, output_dir="result"):
    os.makedirs(output_dir, exist_ok=True)
    csv_file_path = os.path.join(output_dir, f"{evaldir}-scores.csv")
    with open(csv_file_path, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Model"] + list(machine_names) + ["Average"])
        for row in table_data:
            writer.writerow(row)
    print("CSV file saved as:", csv_file_path)
    return csv_file_path

def plot_histogram(csv_file_path):
    scores = []
    models = []
    with open(csv_file_path, 'r') as file:
        csvreader = csv.reader(file)
        next(csvreader)  # Skip the header
        for row in csvreader:
            model = row[0]
            average_score = row[-1]  # Assuming average score is the last column
            if average_score != "-":
                scores.append(float(average_score))
                models.append(model)
    plt.clf()  # Clear previous plots
    plt.bar(models, scores, color='blue')
    plt.title("Average Model Scores")
    plt.xlabel("Models")
    plt.ylabel("Average Score")
    plt.plotsize(100, 30)  # Set the plot size in the terminal
    plt.show()

def main():
    if len(sys.argv) > 1:
        evaldir = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else "result"
        print("Model name:", evaldir)
    else:
        print("No arguments passed. Need at least one model name to evaluate. Check inference.py.")
        exit()

    model_scores = load_scores(evaldir)
    table_data, machine_names = generate_table_data(model_scores)
    save_markdown_table(table_data, machine_names, evaldir, output_dir)
    csv_file_path = save_csv(table_data, machine_names, evaldir, output_dir)
    plot_histogram(csv_file_path)

if __name__ == "__main__":
    main()

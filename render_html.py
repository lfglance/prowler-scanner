from jinja2 import Environment, FileSystemLoader
import config

# Set up Jinja2 environment
env = Environment(loader=FileSystemLoader('html'))

# Load the template
template = env.get_template('template.html')

# Render the template with data from config.py
output = template.render({
    "team_name": config.team_name,
    "template_bucket": config.template_bucket
})

# Save the rendered output to a file
with open('html/index.html', 'w') as f:
    f.write(output)

print("Template rendered successfully to html/output.html")
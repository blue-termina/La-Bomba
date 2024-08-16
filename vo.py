import os

for path, dirs, files in os.walk("."):
for file in files:
lista_file.append(os.path.join(path, file))
for i in lista_file:
print(i)|
import random, os, shutil

def get_random_string(length):
    RANDOM_STRING = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    arr = [None] * length
    for i in range(0, length) :
        arr[i] =  RANDOM_STRING[random.randint(0, len(RANDOM_STRING) - 1)]
    return "".join(arr)

def gen_files(parent_dir, files_count, file_size):
    if os.path.exists(parent_dir) :
        shutil.rmtree(parent_dir)

    os.mkdir(parent_dir)

    files_index=[]
    for i in range(0, files_count) : 
        
        while True:
            name = (get_random_string(10) + '.txt')
            if not (name in files_index):
                files_index.append(name)
                break

        with open(parent_dir + "/" + name, "w") as fd:
            fd.write(get_random_string(file_size))

    with open(parent_dir + "/index.html", "w") as fd:
        first_line = True
        for file in files_index:
            fd.write(('' if first_line else '\n') + file)
            first_line = False
        
if __name__ == '__main__':
    gen_files('html', 10, 8192 * 10)

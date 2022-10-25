# take a disk image as input
# locate file signatures
# properly recover user generated files without corruption
# generate a SHA-255 hash of the recovered files

import os
import hashlib
import argparse
import threading
import logging

def find_all_files(
        data, signatures):
    
    file_locations = {}

    for signature in signatures:
        start = 0
        while True:
            location = data.find(signatures[signature]['start'], start)
            if location == -1:
                break
            if signature not in file_locations:
                file_locations[signature] = []
            file_locations[signature].append(location)
            start += location + 1

    return file_locations


def calculate_file_length(
        data,
        file_signature_location,
        end_signature=None):

    if end_signature is None:
        end_signature = b'\x00\x00\x01\xB9'
    # find the end signature of the file
    file_end = data.find(end_signature, file_signature_location)
    file_length = file_end - file_signature_location

    logging.info(file_end)
    logging.info(file_signature_location)
    logging.info(file_length)

    return file_length

def file_write(
        file_location, 
        file_type, 
        data, 
        out_dir, 
        signatures):
        
    end_signature = signatures[file_type].get('end')
    file_length = calculate_file_length(data, file_location,
                                        end_signature)

    file_data = data[file_location:file_location + file_length]

    file_hash = hashlib.sha256(file_data).hexdigest()

    file_name = f"{file_hash}.{file_type}"

    with open(os.path.join(out_dir, file_name), 'wb') as f:
        f.write(file_data)
    logging.info('File Name: ' + file_name)
    logging.info(f'File Size: {file_length} bytes')
    logging.info('SHA-256 Hash: ' + file_hash)
    


def recover_files(disk_image, out_dir):

    # make the out dir if it doesn't exist
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    # open the disk image
    with open(disk_image, 'rb') as f:
        # read the disk image
        data = f.read()

    # create a list of file signatures
    signatures = {
        # confusion mpg
        "mpg": {
            'start': b'\x00\x00\x01\xBA'
        },
        "pdf": {
            'start': b'\x25\x50\x44\x46'
        },
        "bmp": {
            'start': b'\x42\x4D'
        },
        "gif": {
            'start': b'\x47\x49\x46\x38'
        },
        "jpg": {
            'start': b'\xFF\xD8\xFF\xE0',
            'end': b'\xFF\xD9'
        },
        "docx": {
            'start': b'\x50\x4B\x03\x04'
        },
        "avi": {
            'start': b'\x52\x49\x46\x46'
        },
        "png": {
            'start': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
            'end': b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
        },
        # confusion zip, which ones there are a lot of zip types
        "zip": {
            'start': b'\x50\x4B\x03\x04'
        },
    }

    all_files = find_all_files(data, signatures)

    threads =[]
    for file_type, file_locations in all_files.items():
        for file_location in file_locations:
            thread = threading.Thread(target=file_write,args=(file_location, file_type, data, out_dir, signatures))
            thread.start()
            threads.append(thread)
            
    for thread in threads:
        thread.join()

def main():
    # create the argument parser
    parser = argparse.ArgumentParser()

    # add the out dir and image name as arguments
    parser.add_argument('-i', '--image', help='Disk Image', required=True)
    parser.add_argument('-o', '--out', help='Output Directory', required=True)

    # parse the arguments
    args = parser.parse_args()

    # recover the files
    recover_files(args.image, args.out)


if __name__ == '__main__':
    main()

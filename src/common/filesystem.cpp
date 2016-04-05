/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/**
 * @file        filesystem.cpp
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @version     1.0
 * @brief       Very simple wrapper for opendir/readdir.
 *
 */
#include <sys/types.h>
#include <dirent.h>

#include <vector>
#include <string>

#include <filesystem.h>

namespace SecurityManager {
namespace FS {

FileNameVector getFilesFromDirectory(const std::string &path)
{
    FileNameVector result;
    dirent tmp, *ptr;
    DIR *dir = opendir(path.c_str());

    if (!dir)
        return result;

    while (0 == readdir_r(dir, &tmp, &ptr) && ptr) {
        if (ptr->d_type != DT_REG)
            continue;
        result.push_back(ptr->d_name);
    }

    closedir(dir);
    return result;
}

} // namespace FS
} // nanespace SecurityManager


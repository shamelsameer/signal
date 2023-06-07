#pragma once

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <tuple>

#include <crypto++/cryptlib.h>
#include <crypto++/osrng.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../Eigen/Dense"

using namespace Eigen;

typedef Matrix<long double, Eigen::Dynamic, Eigen::Dynamic> Mat;

class GGHDriver {
public:
  Mat gen_U();
  Mat gen_V();
  std::pair<Mat, Mat> generate();
  Mat encrypt(Mat pk, Mat m, std::optional<Mat> rand);
  Mat decrypt(Mat sk, Mat pk, Mat e);
  Mat byteblock_to_msg(CryptoPP::SecByteBlock block);
  CryptoPP::SecByteBlock msg_to_byteblock(Mat m, size_t nbytes);
  CryptoPP::SecByteBlock copy_to_block(Mat M);
  Mat copy_to_mat(CryptoPP::SecByteBlock block);
  Mat gen_random(int rows, int cols, int range);
  Mat babai(Mat w, Mat V);
  double hadamard_ratio(Mat M);
};

void eigentest();
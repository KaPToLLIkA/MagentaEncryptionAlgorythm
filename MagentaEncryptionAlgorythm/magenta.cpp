#include "magenta.h"

namespace crypto {

    uint8_t magenta::S_box[256] = {
         1  ,  2  ,  4  ,  8  ,  16 ,  32 ,  64 ,  128,
         101,  202,  241,  135,  107,  214,  201,  247,
         139,  115,  230,  169,   55,  110,  220,  221,
         223,  219,  211,  195,  227,  163,   35,   70,
         140,  125,  250,  145,   71,  142,  121,  242,
         129,  103,  206,  249,  151,   75,  150,   73,
         146,   65,  130,   97,  194,  225,  167,   43,
          86,  172,   61,  122,  244,  141,  127,  254,
         153,   87,  174,   57,  114,  228,  173,   63,
         126,  252,  157,   95,  190,   25,   50,  100,
         200,  245,  143,  123,  246,  137,  119,  238,
         185,   23,   46,   92,  184,   21,   42,   84,
         168,   53,  106,  212,  205,  255,  155,   83,
         166,   41,   82,  164,   45,   90,  180,   13,
          26,   52,  104,  208,  197,  239,  187,   19,
          38,   76,  152,   85,  170,   49,   98,  196,
         237,  191,   27,   54,  108,  216,  213,  207,
         251,  147,   67,  134,  105,  210,  193,  231,
         171,   51,  102,  204,  253,  159,   91,  182,
           9,   18,   36,   72,  144,   69,  138,  113,
         226,  161,   39,   78,  156,   93,  186,   17,
          34,   68,  136,  117,  234,  177,    7,   14,
          28,   56,  112,  224,  165,   47,   94,  188,
          29,   58,  116,  232,  181,   15,   30,   60,
         120,  240,  133,  111,  222,  217,  215,  203,
         243,  131,   99,  198,  233,  183,   11,   22,
          44,   88,  176,    5,   10,   20,   40,   80,
         160,   37,   74,  148,   77,  154,   81,  162,
          33,   66,  132,  109,  218,  209,  199,  235,
         179,    3,    6,   12,   24,   48,   96,  192,
         229,  175,   59,  118,  236,  189,   31,   62,
         124,  248,  149,   79,  158,   89,  178,    0
    };

    uint8_t magenta::f(uint8_t byte)
    {
        return S_box[byte];
    }

    uint8_t magenta::A(uint8_t x, uint8_t y)
    {
        return f(x ^ f(y));
    }

    uint16_t magenta::PE(uint8_t x, uint8_t y)
    {
        return (static_cast<uint16_t>(A(x, y)) << 8) | A(y, x);
    }

    block64_t magenta::P(block64_t X)
    {
        return block64_t({
                (static_cast<uint64_t>(PE(BYTE(X[0], 0), BYTE(X[1], 0))) << 48) ^
                (static_cast<uint64_t>(PE(BYTE(X[0], 1), BYTE(X[1], 1))) << 32) ^
                (static_cast<uint64_t>(PE(BYTE(X[0], 2), BYTE(X[1], 2))) << 16) ^
                (static_cast<uint64_t>(PE(BYTE(X[0], 3), BYTE(X[1], 3))) << 0),

                (static_cast<uint64_t>(PE(BYTE(X[0], 4), BYTE(X[1], 4))) << 48) ^
                (static_cast<uint64_t>(PE(BYTE(X[0], 5), BYTE(X[1], 5))) << 32) ^
                (static_cast<uint64_t>(PE(BYTE(X[0], 6), BYTE(X[1], 6))) << 16) ^
                (static_cast<uint64_t>(PE(BYTE(X[0], 7), BYTE(X[1], 7))) << 0)
            });
    }

    block64_t magenta::T(block64_t X)
    {
        return P(P(P(P(X))));
    }

    block64_t magenta::S(block64_t X)
    {
        return block64_t({
                (static_cast<uint64_t>(BYTE(X[0], 0)) << 56) ^
                (static_cast<uint64_t>(BYTE(X[0], 2)) << 48) ^
                (static_cast<uint64_t>(BYTE(X[0], 4)) << 40) ^
                (static_cast<uint64_t>(BYTE(X[0], 6)) << 32) ^
                (static_cast<uint64_t>(BYTE(X[1], 0)) << 24) ^
                (static_cast<uint64_t>(BYTE(X[1], 2)) << 16) ^
                (static_cast<uint64_t>(BYTE(X[1], 4)) << 8) ^
                (static_cast<uint64_t>(BYTE(X[1], 6)) << 0),

                (static_cast<uint64_t>(BYTE(X[0], 1)) << 56) ^
                (static_cast<uint64_t>(BYTE(X[0], 3)) << 48) ^
                (static_cast<uint64_t>(BYTE(X[0], 5)) << 40) ^
                (static_cast<uint64_t>(BYTE(X[0], 7)) << 32) ^
                (static_cast<uint64_t>(BYTE(X[1], 1)) << 24) ^
                (static_cast<uint64_t>(BYTE(X[1], 3)) << 16) ^
                (static_cast<uint64_t>(BYTE(X[1], 5)) << 8) ^
                (static_cast<uint64_t>(BYTE(X[1], 7)) << 0)
            });
    }

    block64_t magenta::C(uint32_t k, block64_t X)
    {
        if (k == 1) 
        {
            return T(X);
        }
        else 
        {
            return T(X ^ S(C(k-1, X)));
        }
    }

    uint64_t magenta::F(block64_t X)
    {
        return S(C(3, (X)))[0];
    }

    block64_t magenta::round_F(block64_t X, uint64_t key)
    {
        return block64_t({
                X[1],
                X[0] ^ F(block64_t({
                        X[1],
                        key
                    }))
            });
    }

    std::vector<block64_t> magenta::split_data(std::vector<byte> data, bool append_service_block)
    {
        std::vector<block64_t> blocks;

        size_t whole_blocks = data.size() / MAGENTA_BLOCK_SZ;

        if (append_service_block)
        {
            size_t last_bytes = data.size() - whole_blocks * MAGENTA_BLOCK_SZ;
            std::random_device rd;
            std::mt19937_64 generator(rd());
            for (size_t i = 0; i < MAGENTA_BLOCK_SZ - last_bytes - 1; ++i) {
                data.push_back(generator() % 256);
            }
            data.push_back(static_cast<byte>(MAGENTA_BLOCK_SZ - last_bytes - 1));
            whole_blocks = data.size() / MAGENTA_BLOCK_SZ;
        }


        block64_t block;
        for (size_t i = 0, pos = 0; i < whole_blocks; ++i)
        {
            for (size_t b = 0; b < block.size(); ++b)
            {
                block[b] =
                    (static_cast<uint64_t>(data[pos]) << 56) ^
                    (static_cast<uint64_t>(data[pos + 1]) << 48) ^
                    (static_cast<uint64_t>(data[pos + 2]) << 40) ^
                    (static_cast<uint64_t>(data[pos + 3]) << 32) ^
                    (static_cast<uint64_t>(data[pos + 4]) << 24) ^
                    (static_cast<uint64_t>(data[pos + 5]) << 16) ^
                    (static_cast<uint64_t>(data[pos + 6]) << 8) ^
                    (static_cast<uint64_t>(data[pos + 7]) << 0);
                pos += 8;
            }
            blocks.push_back(block);
        }

        return blocks;
    }

    block64_t magenta::crypt(block64_t data, std::vector<uint64_t>& keys)
    {
        if (keys.size() == 2) {

            return 
                round_F(
                    round_F(
                        round_F(
                            round_F(
                                round_F(
                                    round_F(
                                        data,
                                        keys[0]), 
                                    keys[0]), 
                                keys[1]), 
                            keys[1]), 
                        keys[0]), 
                    keys[0]);
        }

        if (keys.size() == 3) {

            return 
                round_F(
                    round_F(
                        round_F(
                            round_F(
                                round_F(
                                    round_F(
                                        data, 
                                        keys[0]), 
                                    keys[1]), 
                                keys[2]), 
                            keys[2]), 
                        keys[1]), 
                    keys[0]);
        }

        if (keys.size() == 4) {

            return 
                round_F(
                    round_F(
                        round_F(
                            round_F(
                                round_F(
                                    round_F(
                                        round_F(
                                            round_F(
                                                data, 
                                                keys[0]), 
                                            keys[1]), 
                                        keys[2]), 
                                    keys[3]), 
                                keys[3]), 
                            keys[2]), 
                        keys[1]), 
                    keys[0]);
        }
        
        throw std::runtime_error("Keys vector size error. Size: "
            + std::to_string(keys.size()));
    }

    block64_t magenta::generate_random_iv()
    {
        std::random_device rd;
        std::mt19937_64 generator(rd());
        std::uniform_int_distribution<uint64_t> distribution;

        return block64_t({
                distribution(generator),
                distribution(generator)
            });
    }

    std::vector<byte> magenta::generate_random_key()
    {   
        std::vector<byte> key(sizeof(uint64_t) * 4);

        std::random_device rd;
        std::mt19937_64 generator(rd());
        std::uniform_int_distribution<uint32_t> distribution;

        std::generate(key.begin(), key.end(),
            [&distribution, &generator]() { return distribution(generator); });

        return key;
    }

    magenta::magenta() : raw_key(generate_random_key())
    {
        set_key(this->raw_key);
    }

    magenta::magenta(std::vector<byte>& key)
    {
        try 
        {
            set_key(key);
        }
        catch (...) 
        {
            auto key = generate_random_key();
            set_key(key);
        }
    }

    void magenta::set_key(std::vector<byte>& key)
    {
        size_t key_sz = key.size() / 8;

        if (key.size() % 8 != 0 || key_sz < 2 || key_sz > 4) 
        {
            throw std::runtime_error("Invalid Magenta key size " 
                + std::to_string(key.size()) + 
            " bytes. Must have a length of 16, 24 or 32 bytes.");
        }

        this->raw_key = key;

        this->prepared_key.resize(key_sz);
        for (size_t i = 0, pos = 0; i < key_sz; ++i) 
        {
            this->prepared_key[i] =
                (static_cast<uint64_t>(key[pos]) << 56) ^
                (static_cast<uint64_t>(key[pos + 1]) << 48) ^
                (static_cast<uint64_t>(key[pos + 2]) << 40) ^
                (static_cast<uint64_t>(key[pos + 3]) << 32) ^
                (static_cast<uint64_t>(key[pos + 4]) << 24) ^
                (static_cast<uint64_t>(key[pos + 5]) << 16) ^
                (static_cast<uint64_t>(key[pos + 6]) << 8) ^
                (static_cast<uint64_t>(key[pos + 7]) << 0);
            pos += 8;
        }
    }

    std::vector<byte> magenta::get_key()
    {
        return this->raw_key;
    }

    void magenta::set_file_buf_sz(size_t sz)
    {
        size_t whole_blocks = sz / MAGENTA_BLOCK_SZ;
        this->file_buf_sz = (whole_blocks ? whole_blocks : 1) * MAGENTA_BLOCK_SZ;
    }

    size_t magenta::get_file_buf_sz()
    {
        return this->file_buf_sz;
    }

    std::vector<byte> magenta::encrypt(std::vector<byte>* data)
    {
        auto iv = generate_random_iv();

        auto blocks = split_data(*data);

        std::vector<byte> result;
        result = result + iv;

        for (const auto& block : blocks) {
            iv = crypt(iv ^ block, this->prepared_key);
            result = result + iv;
        }

        return result;
    }

    std::vector<byte> magenta::encrypt(std::vector<byte> data)
    {
        return encrypt(&data);
    }

    std::vector<byte> magenta::decrypt(std::vector<byte>* data)
    {
        auto blocks = split_data(*data, false);

        auto iv = blocks[0];

        std::vector<byte> result;

        for (size_t i = 1; i < blocks.size(); ++i)
        {
            auto raw_decoded = crypt(block64_t({ blocks[i][1] , blocks[i][0] }), this->prepared_key);
            auto decoded = iv ^ block64_t({ raw_decoded[1], raw_decoded[0] });
            result = result + decoded;
            iv = blocks[i];
        }

        auto first = result.end() - 1 - static_cast<int32_t>(*(--result.end()));
        auto last = result.end();

        result.erase(first, last);

        return result;
    }

    std::vector<byte> magenta::decrypt(std::vector<byte> data)
    {
        return decrypt(&data);
    }

    std::string magenta::encrypt_file(std::string* fname)
    {
        std::ifstream fin(*fname, std::ios_base::binary);
        if (!fin.is_open())
        {
            throw std::runtime_error("Unable to open the \"" + *fname + "\" file.");
        }
        std::ofstream fout((*fname) + ".encrypted", std::ios_base::binary | std::ios_base::trunc);

        std::streampos cur = fin.tellg(), last = fin.tellg();
        size_t len = cur - last;
        fin.seekg(0, std::ios::end);
        size_t f_len = fin.tellg();
        fin.seekg(0, std::ios::beg);

        auto iv = generate_random_iv();
        fout.write(reinterpret_cast<char*>(iv.data()), MAGENTA_BLOCK_SZ);

        bool file_ended = false;
        char t;

        do
        {
            std::vector<byte> data(this->file_buf_sz);
            fin.read(reinterpret_cast<char*>(data.data()), data.size());

            fin.read(&t, 1);
            file_ended = fin.eof();
            fin.seekg(-1, std::ios::cur);

            cur = fin.tellg();
            len = cur != -1 ? cur - last : f_len - last;
            last = cur;

            data.resize(len);

            auto blocks = split_data(data, file_ended);

            std::vector<byte> result;
            for (const auto& block : blocks)
            {
                iv = crypt(iv ^ block, this->prepared_key);
                result = result + iv;
            }

            fout.write(reinterpret_cast<char*>(result.data()), result.size());

        } while (!file_ended);

        fout.close();
        fin.close();
        return (*fname) + ".encrypted";
    }

    std::string magenta::encrypt_file(std::string fname)
    {
        return encrypt_file(&fname);
    }

    std::string magenta::decrypt_file(std::string* fname)
    {
        std::ifstream fin(*fname, std::ios_base::binary);
        if (!fin.is_open())
        {
            throw std::runtime_error("Unable to open the \"" + *fname + "\" file.");
        }
        std::ofstream fout((*fname) + ".decrypted", std::ios_base::binary | std::ios_base::trunc);

        std::streampos cur = fin.tellg(), last = fin.tellg();
        size_t len = cur - last;
        fin.seekg(0, std::ios::end);
        size_t f_len = fin.tellg();
        fin.seekg(0, std::ios::beg);

        block64_t iv;
        fin.read(reinterpret_cast<char*>(iv.data()), MAGENTA_BLOCK_SZ);

        cur = fin.tellg();
        last = cur;

        bool file_ended = false;
        char t;

        do
        {
            std::vector<byte> data(this->file_buf_sz);
            fin.read(reinterpret_cast<char*>(data.data()), data.size());

            fin.read(&t, 1);
            file_ended = fin.eof();
            fin.seekg(-1, std::ios::cur);

            cur = fin.tellg();
            len = cur != -1 ? cur - last : f_len - last;
            last = cur;

            data.resize(len);

            auto blocks = split_data(data, false);

            std::vector<byte> result;
            for (const auto& block : blocks)
            {
                auto raw_decoded = crypt(block64_t({ block[1] , block[0] }), this->prepared_key);
                auto decoded = iv ^ block64_t({ raw_decoded[1], raw_decoded[0] });
                result = result + decoded;
                iv = block;
            }

            if (file_ended)
            {
                auto first = result.end() - 1 - static_cast<int32_t>(*(--result.end()));
                auto last = result.end();

                result.erase(first, last);
            }

            fout.write(reinterpret_cast<char*>(result.data()), result.size());

        } while (!file_ended);

        fout.close();
        fin.close();
        return (*fname) + ".decrypted";
    }

    std::string magenta::decrypt_file(std::string fname)
    {
        return decrypt_file(&fname);
    }

    block64_t operator^(const block64_t& a, const block64_t& b)
    {
        return block64_t({
                a[0] ^ b[0],
                a[1] ^ b[1]
            });
    }

    std::vector<byte>& operator+(std::vector<byte>& a, const block64_t& b)
    {
        for (size_t bi = 0; bi < 2; ++bi)
        {
            for (size_t i = 0; i < 8; ++i)
            {
                a.push_back(BYTE(b[bi], i));
            }
        }
        return a;
    }

} // end crypto namespace

#pragma once

class chacha20;
class randomgen {

    std::unique_ptr<chacha20> chacha;
    void rnd(void* const buf, size_t size); // extra rnd
public:
    randomgen()
    {
    }

    void clear() { chacha.reset(); }
    void randombytes_buf(void* const buf, size_t size);
    void random_vec(std::span<uint8_t> v) { this->randombytes_buf(v.data(), v.size()); }
};


class BotanRndGen : public Botan::RandomNumberGenerator, public randomgen
{
public:
    void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /*input*/) override
    {
        randomgen::random_vec(output);
    }

    bool accepts_input() const override { return false; }
    void clear() override { randomgen::clear(); }
    bool is_seeded() const override { return true; }
};
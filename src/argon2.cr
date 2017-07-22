@[Link("argon2")]
lib LibArgon2
    ARGON2_MIN_LANES = 1_u32
    ARGON2_MAX_LANES = 0xFFFFFF_u32

    ARGON2_MIN_THREADS = 1_u32
    ARGON2_MAX_THREADS = 0xFFFFFF_u32

    ARGON2_SYNC_POINTS = 4_u32

    ARGON2_MIN_OUTLEN = 4_u32
    ARGON2_MAX_OUTLEN = 0xFFFFFFFF_u32

    ARGON2_MIN_TIME = 1_u32
    ARGON2_MAX_TIME = 0xFFFFFFFF_u32

    ARGON2_MIN_PWD_LENGTH = 0_u32
    ARGON2_MAX_PWD_LENGTH = 0xFFFFFFFF_u32

    ARGON2_MIN_AD_LENGTH = 0_u32
    ARGON2_MAX_AD_LENGTH = 0xFFFFFFFF_u32

    ARGON2_MIN_SALT_LENGTH = 8_u32
    ARGON2_MAX_SALT_LENGTH = 0xFFFFFFFF_u32

    ARGON2_MIN_SECRET = 0_u32
    ARGON2_MAX_SECRET = 0xFFFFFFFF_u32

    ARGON2_DEFAULT_FLAGS = 0_u32
    ARGON2_FLAG_CLEAR_PASSWORD = (1_u32 << 0)
    ARGON2_FLAG_CLEAR_SECRET = (1_u32 << 1)

    enum ErrorCodes
        ARGON2_OK = 0

        ARGON2_OUTPUT_PTR_NULL = -1

        ARGON2_OUTPUT_TOO_SHORT = -2
        ARGON2_OUTPUT_TOO_LONG = -3

        ARGON2_PWD_TOO_SHORT = -4
        ARGON2_PWD_TOO_LONG = -5

        ARGON2_SALT_TOO_SHORT = -6
        ARGON2_SALT_TOO_LONG = -7

        ARGON2_AD_TOO_SHORT = -8
        ARGON2_AD_TOO_LONG = -9

        ARGON2_SECRET_TOO_SHORT = -10
        ARGON2_SECRET_TOO_LONG = -11

        ARGON2_TIME_TOO_SMALL = -12
        ARGON2_TIME_TOO_LARGE = -13

        ARGON2_MEMORY_TOO_LITTLE = -14
        ARGON2_MEMORY_TOO_MUCH = -15

        ARGON2_LANES_TOO_FEW = -16
        ARGON2_LANES_TOO_MANY = -17

        ARGON2_PWD_PTR_MISMATCH = -18
        ARGON2_SALT_PTR_MISMATCH = -19
        ARGON2_SECRET_PTR_MISMATCH = -20
        ARGON2_AD_PTR_MISMATCH = -21

        ARGON2_MEMORY_ALLOCATION_ERROR = -22

        ARGON2_FREE_MEMORY_CBK_NULL = -23
        ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24

        ARGON2_INCORRECT_PARAMETER = -25
        ARGON2_INCORRECT_TYPE = -26

        ARGON2_OUT_PTR_MISMATCH = -27

        ARGON2_THREADS_TOO_FEW = -28
        ARGON2_THREADS_TOO_MANY = -29

        ARGON2_MISSING_ARGS = -30

        ARGON2_ENCODING_FAIL = -31

        ARGON2_DECODING_FAIL = -32

        ARGON2_THREAD_FAIL = -33

        ARGON2_DECODING_LENGTH_FAIL = -34

        ARGON2_VERIFY_MISMATCH = -35
    end

    alias AllocateFptr = (UInt8**, LibC::SizeT -> Int32)
    alias DeallocateFptr = (UInt8**, LibC::SizeT -> Void)

    struct Context
        pout : UInt8*
        outlen : UInt32
        ppwd : UInt8*
        pwdlen : UInt32
        psalt : UInt8*
        saltlen : UInt32
        psecret : UInt8*
        secretlen : UInt32
        pad : UInt8*
        adlen : UInt32
        time_cost : UInt32
        mem_cost : UInt32
        lanes : UInt32
        threads : UInt32
        version : UInt32
        allocate_cbk : AllocateFptr
        deallocate_cbk : DeallocateFptr
        flags : UInt32
    end

    enum HashType
        Dependent = 0
        Independent = 1
        Mixed = 2
    end

    enum Version
        ARGON2_VERSION_10 = 0x10
        ARGON2_VERSION_13 = 0x13
        ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
    end

    # Function that gives the string representation of an argon2_type.
    # @param type The argon2_type that we want the string for
    # @param uppercase Whether the string should have the first letter uppercase
    # @return NULL if invalid type, otherwise the string representation.
    fun argon2_type2string(t : HashType, uppercase : Int32) : UInt8*

    # Function that performs memory-hard hashing with certain degree of parallelism
    # @param  context  Pointer to the Argon2 internal structure
    # @return Error code if smth is wrong, ARGON2_OK otherwise
    fun argon2_ctx(context : Context*, t : HashType) : ErrorCodes

    # Hashes a password with Argon2i, producing an encoded hash
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    # @param parallelism Number of threads and compute lanes
    # @param pwd Pointer to password
    # @param pwdlen Password size in bytes
    # @param salt Pointer to salt
    # @param saltlen Salt size in bytes
    # @param hashlen Desired length of the hash in bytes
    # @param encoded Buffer where to write the encoded hash
    # @param encodedlen Size of the buffer (thus max size of the encoded hash)
    # @pre   Different parallelism levels will give different results
    # @pre   Returns ARGON2_OK if successful
    fun argon2i_hash_encoded(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                             pwd : Void*, pwdlen : LibC::SizeT,
                             salt : Void*, saltlen : LibC::SizeT,
                             hashlen : LibC::SizeT,
                             encoded : UInt8*, encodedlen : LibC::SizeT) : ErrorCodes

    # Hashes a password with Argon2i, producing a raw hash by allocating memory at @hash
    # @param t_cost Number of iterations
    # @param m_cost Sets memory usage to m_cost kibibytes
    # @param parallelism Number of threads and compute lanes
    # @param pwd Pointer to password
    # @param pwdlen Password size in bytes
    # @param salt Pointer to salt
    # @param saltlen Salt size in bytes
    # @param hash Buffer where to write the raw hash - updated by the function
    # @param hashlen Desired length of the hash in bytes
    # @pre   Different parallelism levels will give different results
    # @pre   Returns ARGON2_OK if successful
    fun argon2i_hash_raw(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                         pwd : Void*, pwdlen : LibC::SizeT,
                         salt : Void*, saltlen : LibC::SizeT,
                         hash : Void*, hashlen : LibC::SizeT) : ErrorCodes

    fun argon2d_hash_encoded(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                             pwd : Void*, pwdlen : LibC::SizeT,
                             salt : Void*, saltlen : LibC::SizeT,
                             hashlen : LibC::SizeT, encoded : UInt8*,
                             encodedlen : LibC::SizeT) : ErrorCodes

    fun argon2d_hash_raw(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                         pwd : Void*, pwdlen : LibC::SizeT,
                         salt : Void*, saltlen : LibC::SizeT,
                         hash : Void*, hashlen : LibC::SizeT) : ErrorCodes

    fun argon2id_hash_encoded(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                              pwd : Void*, pwdlen : LibC::SizeT,
                              salt : Void*, saltlen : LibC::SizeT,
                              hashlen : LibC::SizeT, encoded : UInt8*,
                              encodedlen : LibC::SizeT) : ErrorCodes

    fun argon2id_hash_raw(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                          pwd : Void*, pwdlen : LibC::SizeT,
                          salt : Void*, saltlen : LibC::SizeT,
                          hash : Void*, hashlen : LibC::SizeT) : ErrorCodes

    fun argon2_hash(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                    pwd : Void*, pwdlen : LibC::SizeT,
                    salt : Void*, saltlen : LibC::SizeT,
                    hash : Void*, hashlen : LibC::SizeT,
                    encoded : UInt8*, encodedlen : LibC::SizeT,
                    t : HashType, version : Version) : ErrorCodes

    # Verifies a password against an encoded string
    # Encoded string is restricted as in validate_inputs()
    # @param encoded String encoding parameters, salt, hash
    # @param pwd Pointer to password
    # @pre   Returns ARGON2_OK if successful
    fun argon2i_verify(encoded : UInt8*, pwd : Void*, pwdlen : LibC::SizeT) : ErrorCodes
    fun argon2d_verify(encoded : UInt8*, pwd : Void*, pwdlen : LibC::SizeT) : ErrorCodes
    fun argon2id_verify(encoded : UInt8*, pwd : Void*, pwdlen : LibC::SizeT) : ErrorCodes
    fun argon2_verify(encoded : UInt8*, pwd : Void*, pwdlen : LibC::SizeT, t : HashType) : ErrorCodes

    # Argon2d: Version of Argon2 that picks memory blocks depending
    # on the password and salt. Only for side-channel-free
    # environment!!
    #
    # @param  context  Pointer to current Argon2 context
    # @return  Zero if successful, a non zero error code otherwise
    fun argon2d_ctx(context : Context*) : ErrorCodes

    # Argon2i: Version of Argon2 that picks memory blocks
    # independent on the password and salt. Good for side-channels,
    # but worse w.r.t. tradeoff attacks if only one pass is used.
    # 
    # @param  context  Pointer to current Argon2 context
    # @return  Zero if successful, a non zero error code otherwise
    fun argon2i_ctx(context : Context*) : ErrorCodes

    # Argon2id: Version of Argon2 where the first half-pass over memory is
    # password-independent, the rest are password-dependent (on the password and
    # salt). OK against side channels (they reduce to 1/2-pass Argon2i), and
    # better with w.r.t. tradeoff attacks (similar to Argon2d).
    # 
    # @param  context  Pointer to current Argon2 context
    # @return  Zero if successful, a non zero error code otherwise
    fun argon2id_ctx(context : Context*) : ErrorCodes

    # Verify if a given password is correct for Argon2d hashing
    # @param  context  Pointer to current Argon2 context
    # @param  hash  The password hash to verify. The length of the hash is
    # specified by the context outlen member
    # @return  Zero if successful, a non zero error code otherwise
    fun argon2d_verify_ctx(context : Context*, hash : UInt8*) : ErrorCodes

    # Verify if a given password is correct for Argon2i hashing
    # @param  context  Pointer to current Argon2 context
    # @param  hash  The password hash to verify. The length of the hash is
    # specified by the context outlen member
    # @return  Zero if successful, a non zero error code otherwise
    fun argon2i_verify_ctx(context : Context*, hash : UInt8*) : ErrorCodes

    # Verify if a given password is correct for Argon2id hashing
    # @param  context  Pointer to current Argon2 context
    # @param  hash  The password hash to verify. The length of the hash is
    # specified by the context outlen member
    # @return  Zero if successful, a non zero error code otherwise
    fun argon2id_verify_ctx(context : Context*, hash : UInt8*) : ErrorCodes

    fun argon2_verify_ctx(context : Context*, hash : UInt8*, t : HashType) : ErrorCodes

    # Get the associated error message for given error code
    # @return  The error message associated with the given error code
    fun argon2_error_message(error_code : ErrorCodes) : UInt8*

    # Returns the encoded hash length for the given input parameters
    # @param t_cost  Number of iterations
    # @param m_cost  Memory usage in kibibytes
    # @param parallelism  Number of threads; used to compute lanes
    # @param saltlen  Salt size in bytes
    # @param hashlen  Hash size in bytes
    # @return  The encoded hash length in bytes
    fun argon2_encodedlen(t_cost : Int32, m_cost : UInt32, parallelism : UInt32,
                          saltlen : UInt32, hashlen : UInt32, t : HashType) : LibC::SizeT
end

class Argon2
    @mem_cost : UInt32
    @parallelism : UInt32
    @time_cost : Int32

    def initialize(@time_cost : Int32, mem_cost : UInt32, @parallelism : UInt32)
        @mem_cost = mem_cost << 16
    end

    def hash_encoded(password : String, salt : String, hash_length : UInt32,
                     hash_type : LibArgon2::HashType) : String
        encodedlen = LibArgon2.argon2_encodedlen(
            @time_cost, @mem_cost, @parallelism,
            salt.bytesize, hash_length, hash_type
        )
        encoded = Array(UInt8).new(encodedlen, 0_u8)

        case hash_type
            when LibArgon2::HashType::Dependent
                hash_method = ->LibArgon2.argon2d_hash_encoded
            when LibArgon2::HashType::Independent
                hash_method = ->LibArgon2.argon2i_hash_encoded
            when LibArgon2::HashType::Mixed
                hash_method = ->LibArgon2.argon2id_hash_encoded
            else
                hash_method = nil
        end

        if hasher = hash_method
            err = hasher.call(@time_cost, @mem_cost, @parallelism,
                            password.to_unsafe.as(Void*), LibC::SizeT.new(password.bytesize),
                            salt.to_unsafe.as(Void*), LibC::SizeT.new(salt.bytesize),
                            LibC::SizeT.new(hash_length),
                            encoded.to_unsafe, encodedlen)
            if err == LibArgon2::ErrorCodes::ARGON2_OK
                return String.new(encoded.to_unsafe)
            end
            raise Exception.new("An error occured during hashing (Argon2): #{String.new(LibArgon2.argon2_error_message(err))}")
        end

        raise ArgumentError.new("Argon2: Unknown hash type")
    end

    def hash_encoded_d(password : String, salt : String, hash_length : UInt32) : String
        return self.hash_encoded(password, salt, hash_length, LibArgon2::HashType::Dependent)
    end

    def hash_encoded_i(password : String, salt : String, hash_length : UInt32) : String
        return self.hash_encoded(password, salt, hash_length, LibArgon2::HashType::Independent)
    end

    def hash_encoded_m(password : String, salt : String, hash_length : UInt32) : String
        return self.hash_encoded(password, salt, hash_length, LibArgon2::HashType::Mixed)
    end

    def self.verify(encoded : String, password : String, hash_type : LibArgon2::HashType) : Bool
        return LibArgon2.argon2_verify(encoded.to_unsafe, password.to_unsafe.as(Void*), LibC::SizeT.new(password.bytesize), hash_type) == LibArgon2::ErrorCodes::ARGON2_OK
    end

    def self.verify_d(encoded : String, password : String) : Bool
        return self.verify(encoded, password, LibArgon2::HashType::Dependent)
    end

    def self.verify_i(encoded : String, password : String) : Bool
        return self.verify(encoded, password, LibArgon2::HashType::Independent)
    end

    def self.verify_m(encoded : String, password : String) : Bool
        return self.verify(encoded, password, LibArgon2::HashType::Mixed)
    end
end

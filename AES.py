import math

#Rijndael's substitution box for sub_bytes step */
SBOX = [
     [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 ],
     [ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 ],
     [ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 ],
     [ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 ],
     [ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 ],
     [ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf ],
     [ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 ],
     [ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 ],
     [ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 ],
     [ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb ],
     [ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 ],
     [ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 ],
     [ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a ],
     [ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e ],
     [ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf ],
     [ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
]

#Inverse S-Box
INV_SBOX = [
     [ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB ],
     [ 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB ],
     [ 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E ],
     [ 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 ],
     [ 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 ],
     [ 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 ],
     [ 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 ],
     [ 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B ],
     [ 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 ],
     [ 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E ],
     [ 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B ],
     [ 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 ],
     [ 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F ],
     [ 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF ],
     [ 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 ],
     [ 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D ]
]


def rcon( num ):
    exp = num / 4 - 1
    if( num <= 32 ):
        res = math.pow( 2, exp )
    else:
        res = 27 * (num / 4 - 8)
    
    res = int( res ) << 24 
    return res
    #print( hex(res) )
    #print( "geldii" )

def expand_key( key ):
    expanded_key = []
    temp = []
    
    for i in range( 0, 4 ):
        temp.append( 0 )
    
    for i in range( 0, 44*4 ):
        expanded_key.append( 0 )

    for i in range( 0, 4 ):
        expanded_key[ i*4 +0 ] = key[ (i*4) ]
        expanded_key[ i*4 +1 ] = key[ (i*4 +1) ]
        expanded_key[ i*4 +2 ] = key[ (i*4 +2) ]
        expanded_key[ i*4 +3 ] = key[ (i*4 +3) ]
    
    for i in range( 4, 44 ):
        #temp = w[i-1]
        temp[0] = expanded_key[4*(i-1) + 0]
        temp[1] = expanded_key[4*(i-1) + 1]
        temp[2] = expanded_key[4*(i-1) + 2]
        temp[3] = expanded_key[4*(i-1) + 3]
       
        if( i % 4 == 0 ):
            #rot_word(temp)
            temp_int = temp[0]
            temp[0] = temp[1]
            temp[1] = temp[2]
            temp[2] = temp[3]
            temp[3] = temp_int
            

            #sub_word( temp )
            c = temp[0] & 0x0f
            r = temp[0] >> 4
            temp[0] = SBOX[ r ][ c ]

            c = temp[1] & 0x0f
            r = temp[1] >> 4
            temp[1] = SBOX[ r ][ c ]

            c = temp[2] & 0x0f
            r = temp[2] >> 4
            temp[2] = SBOX[ r ][ c ]

            c = temp[3] & 0x0f
            r = temp[3] >> 4
            temp[3] = SBOX[ r ][ c ]


            #temp xor rcon
            temp[0] = temp[0] ^ (rcon( i ) >> 24 )
            temp[1] = temp[1] ^ 0x00
            temp[2] = temp[2] ^ 0x00
            temp[3] = temp[3] ^ 0x00
            
            """print( hex(temp[0]), end=" " )
            print( hex(temp[1]), end=" " )
            print( hex(temp[2]), end=" " )
            print( hex(temp[3]), end="\n\n" )"""       
        #elif( Nk > 6 and i % Nk = 4 )
        
        expanded_key[ i*4 +0 ] = expanded_key[ (i-4)*4 +0 ] ^ temp[0]
        expanded_key[ i*4 +1 ] = expanded_key[ (i-4)*4 +1 ] ^ temp[1]
        expanded_key[ i*4 +2 ] = expanded_key[ (i-4)*4 +2 ] ^ temp[2]
        expanded_key[ i*4 +3 ] = expanded_key[ (i-4)*4 +3 ] ^ temp[3]
    return expanded_key


def galua_mult_with_two( num ):
    if num < 0x80:
        result = num << 1
    else:
        result = (num << 1) ^ 0x1b
    result = result % 0x100
    return result

def galua_multiplication( coefficient, num ):
    if( coefficient == 2 ):
        result = galua_mult_with_two( num )    
    
    elif( coefficient == 3 ):
        result = galua_mult_with_two( num )
        result = result ^ num

    elif( coefficient == 9 ):
        result = galua_mult_with_two( num )
        result = galua_mult_with_two( result )
        result = galua_mult_with_two( result )
        result = result ^ num

    elif( coefficient == 0xb ):
        result = galua_mult_with_two( num )
        result = galua_mult_with_two( result )
        result = galua_mult_with_two( result )
        result = result ^ galua_mult_with_two( num ) ^ num        
    
    elif( coefficient == 0xd ):
        n1 = galua_mult_with_two( num )
        n1 = galua_mult_with_two( n1 )
        n1 = galua_mult_with_two( n1 )
        
        n2 = galua_mult_with_two( num )
        n2 = galua_mult_with_two( n2 )
        
        result = n1 ^ n2 ^ num
        
    elif( coefficient == 0xe ):
        n1 = galua_mult_with_two( num )
        n1 = galua_mult_with_two( n1 )
        n1 = galua_mult_with_two( n1 )
        
        n2 = galua_mult_with_two( num )
        n2 = galua_mult_with_two( n2 )
        
        result = n1 ^ n2 ^ galua_mult_with_two( num )
    return result
    
def inverse_mix_columns(state):
    #p = product of two number   #r = row_element
    for i in range(0, 4):
        p0 = galua_multiplication(0xe, state[0][i])
        p1 = galua_multiplication(0xb, state[1][i])
        p2 = galua_multiplication(0xd, state[2][i])
        p3 = galua_multiplication(9, state[3][i])
        r0 = p0 ^ p1 ^ p2 ^ p3
    
        p0 = galua_multiplication(9, state[0][i])
        p1 = galua_multiplication(0xe, state[1][i])
        p2 = galua_multiplication(0xb, state[2][i])
        p3 = galua_multiplication(0xd, state[3][i])
        r1 = p0 ^ p1 ^ p2 ^ p3
        
        p0 = galua_multiplication(0xd, state[0][i])
        p1 = galua_multiplication(9, state[1][i])
        p2 = galua_multiplication(0xe, state[2][i])
        p3 = galua_multiplication(0xb, state[3][i])
        r2 = p0 ^ p1 ^ p2 ^ p3
        
        p0 = galua_multiplication(0xb, state[0][i])
        p1 = galua_multiplication(0xd, state[1][i])
        p2 = galua_multiplication(0x9, state[2][i])
        p3 = galua_multiplication(0xe, state[3][i])
        r3 = p0 ^ p1 ^ p2 ^ p3

        state[0][i] = r0
        state[1][i] = r1
        state[2][i] = r2
        state[3][i] = r3

def mix_columns(state):
    #p = product of two number   #r = row_element
    for i in range(0, 4):
        p0 = galua_multiplication(2, state[0][i])
        p1 = galua_multiplication(3, state[1][i])
        p2 = state[2][i]
        p3 = state[3][i]
        r0 = p0 ^ p1 ^ p2 ^ p3
    
        p0 = state[0][i]
        p1 = galua_multiplication(2, state[1][i])
        p2 = galua_multiplication(3, state[2][i])
        p3 = state[3][i]
        r1 = p0 ^ p1 ^ p2 ^ p3
        
        p0 = state[0][i]
        p1 = state[1][i]
        p2 = galua_multiplication(2, state[2][i])
        p3 = galua_multiplication(3, state[3][i])
        r2 = p0 ^ p1 ^ p2 ^ p3
        
        p0 = galua_multiplication(3, state[0][i])
        p1 = state[1][i]
        p2 = state[2][i]
        p3 = galua_multiplication(2, state[3][i])
        r3 = p0 ^ p1 ^ p2 ^ p3

        state[0][i] = r0
        state[1][i] = r1
        state[2][i] = r2
        state[3][i] = r3




def substitute( num ):
    c = num & 0x0f
    r = num >> 4
    result = SBOX[ r ][ c ]    
    return result

def inverse_substitute( num ):
    c = num & 0x0f
    r = num >> 4
    result = INV_SBOX[ r ][ c ]    
    return result

#shifts to left
def left_shift( row, num_of ):
    for i in range( 0, num_of ):
        temp = row[0]
        row[0] = row[1]
        row[1] = row[2]
        row[2] = row[3]
        row[3] = temp

def right_shift( row, num_of ):
    for i in range( 0, num_of ):    
        temp = row[3]
        row[3] = row[2]
        row[2] = row[1]
        row[1] = row[0]
        row[0] = temp
        
def inverse_shift_rows(matrix):
    right_shift( matrix[1], 1 )
    right_shift( matrix[2], 2 )
    right_shift( matrix[3], 3 )     
        


def shift_rows( matrix ):
    left_shift( matrix[1], 1 )
    left_shift( matrix[2], 2 )
    left_shift( matrix[3], 3 )    
    

def convert_to_matrix( linear_form, index ):
    matrix = [ [0, 0, 0, 0],
               [0, 0, 0, 0],
               [0, 0, 0, 0],
               [0, 0, 0, 0] ]
               
    matrix[0][0] = linear_form[0 + 16*index]
    matrix[1][0] = linear_form[1 + 16*index]
    matrix[2][0] = linear_form[2 + 16*index]
    matrix[3][0] = linear_form[3 + 16*index ]
    
    matrix[0][1] = linear_form[4 + 16*index]
    matrix[1][1] = linear_form[5 + 16*index]
    matrix[2][1] = linear_form[6 + 16*index]
    matrix[3][1] = linear_form[7 + 16*index ]

    matrix[0][2] = linear_form[8 + 16*index]
    matrix[1][2] = linear_form[9 + 16*index]
    matrix[2][2] = linear_form[10 + 16*index]
    matrix[3][2] = linear_form[11 + 16*index ]
    
    matrix[0][3] = linear_form[12 + 16*index]
    matrix[1][3] = linear_form[13 + 16*index]
    matrix[2][3] = linear_form[14 + 16*index]
    matrix[3][3] = linear_form[15 + 16*index ]
    
    return matrix

def convert_to_line( matrix ):
    index = 0
    line = []
    for col in range( 0, 4 ):
        for row in range( 0, 4 ):
            line.append( matrix[row][col] )
            index += 1
    return line    
    

def print_matrix( matrix ):
    print( "" )
    for i in range( 0, 4 ):
        for j in range( 0, 4 ):
            print( hex( matrix[i][j] ), end="  " )
        print( "" )
    print( "" )

def add_round_key( state, round_key ):
    for i in range( 0, 4 ):
        for j in range( 0, 4 ):
            state[i][j] = state[i][j] ^ round_key[i][j]

def substitute_all( state ):
    for i in range( 0, 4 ):
        for j in range( 0, 4 ):
            state[i][j] = substitute( state[i][j] )

def inv_substitute_all( state ):
    for i in range( 0, 4 ):
        for j in range( 0, 4 ):
            state[i][j] = inverse_substitute( state[i][j] )



def encrypt( plain, key ):
    state = convert_to_matrix( plain, 0 )
    expanded_key = expand_key( key )
    round_key = convert_to_matrix( expanded_key, 0 )
    add_round_key( state, round_key )

    for i in range(0, 9):
        substitute_all( state )
        shift_rows( state )
        mix_columns( state )
        round_key = convert_to_matrix( expanded_key, i+1 )
        add_round_key( state, round_key )
    substitute_all( state )
    shift_rows( state )
    round_key = convert_to_matrix( expanded_key, 10 )
    add_round_key( state, round_key )
    
    chipper = convert_to_line( state )
    return chipper


def decrypt( chipper, key ):
    state = convert_to_matrix( chipper, 0 )
    #state = chipper
    expanded_key = expand_key( key )
    round_key = convert_to_matrix( expanded_key, 10 )
    add_round_key( state, round_key )

    for i in range( 9, 0, -1 ):
        inverse_shift_rows( state )
        inv_substitute_all(state)
        round_key = convert_to_matrix( expanded_key, i )
        add_round_key( state, round_key )
        inverse_mix_columns( state )

    inverse_shift_rows( state )
    inv_substitute_all(state)
    round_key = convert_to_matrix( expanded_key, 0 )
    add_round_key( state, round_key )
    
    palin_text = convert_to_line( state )
    return palin_text


plain = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
key = [0x2b, 0x7e, 0x15,  0x16,  0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

print( "\nThe list in below is 16Byte. And it will be encrypted with AES." )
for i in range( 0, 16 ):
    print( hex(plain[i]), end=" " )
print( "" )
input( "Press enter to continue." )

print( "\nThe below 16 Byte will be used as a key for the AES encryption." )
for i in range( 0, 16 ):
    print( hex(key[i]), end=" " )
print( "" )
input( "Press enter to continue." )


print( "\nThe encrypted 16 Byte is in below:" )
chipper =  encrypt( plain, key )
for i in range( 0, 16 ):
    print( hex(chipper[i]), end=" " )
print( "" )
input( "Press enter to continue." )

print( "\nThe above encrypted 16 Byte is decrypted using the key." )
print( "The decrypted 16 Byte is in below:" )
plain_text = decrypt( chipper, key )
for i in range( 0, 16 ):
    print( hex(plain_text[i]), end=" " )
print( "" )
input( "Press enter to halt the program." )




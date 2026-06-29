if(CONFIG_MLKEM_512) 
    set(SUBDIR clean512)
elseif(CONFIG_MLKEM_768) 
    set(SUBDIR clean768) 
elseif(CONFIG_MLKEM_1024)
    set(SUBDIR clean1024) 
endif() 

file(GLOB 
    SRCS
        ${SUBDIR}/*.c 
        src/mlkem.c 
    ) 
    
idf_component_register( 
    SRCS 
        ${SRCS} 
    INCLUDE_DIRS 
        ${SUBDIR}
        "include"
    )
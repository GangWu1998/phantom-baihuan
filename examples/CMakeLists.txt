add_executable(example_context
        1_bfv.cu
        2_bgv.cu
        3_ckks.cu
        4_kernel_fusing.cu
        example.cu
)
target_link_libraries(example_context PRIVATE Phantom)
target_include_directories(example_context PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(example_serialization
        serialization.cu
)
target_link_libraries(example_serialization PRIVATE Phantom ${NTL_LIBRARY} ${GMP_LIBRARY} pthread)
target_include_directories(example_serialization PRIVATE ${CMAKE_SOURCE_DIR}/include )
# target_link_libraries(example_serialization PRIVATE )
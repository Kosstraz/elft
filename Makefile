# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: bama <bama@student.42.fr>                  +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/05/13 16:21:19 by ymanchon          #+#    #+#              #
#    Updated: 2025/03/15 13:52:48 by bama             ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

# ################ #
#*    COULEURS    *#
# ################ #

CLASSIC	= \e[0m
WHITE	= \e[38;2;238;232;213m
BOLD	= \e[1m
# BLACK	= \e[38;2;0;0;0m
BLACK	= \e[30m
RED   	= \e[31m
GREEN  	= \e[32m
BLUE 	= \e[38;2;0;36;148m
PURPLE 	= \e[38;2;211;54;130m
CYAN   	= \e[36m
YELLOW 	= \e[38;2;250;189;0m

# ############### #
#*   VARIABLES   *#
# ############### #

NAME = libelft.a

AR = @ar -rcs

CC = @cc

LMAKE = @make $(1) --no-print-directory -C $(2)

SRCS =	./elft.c \
		./elft_read.c \
		./elft_sym.c \
		./elft_find.c \
		./elft_free.c \
		./__elft_utils.c \

OBJS_DIR = .objs

OBJS = $(SRCS:%.c=$(OBJS_DIR)/%.obj)

DEPS = $(OBJS:%.obj=%.d)

CFLAGS = -Wall -Wextra -Wno-unused-result -MMD -g3

INCLUDES = -I.

# ############## #
#*    REGLES    *#
# ############## #

all: check_compilation $(NAME)

$(NAME): $(OBJS)
	$(AR) $(NAME) -o $(OBJS)
	@echo "$(BOLD)$(CYAN)Exécutable $(NAME) créé avec succès!$(CLASSIC)"

$(OBJS_DIR)/%.obj: %.c
	@mkdir -p $(@D)
	@echo "$(GREEN)🗸 Compilation $(BOLD)$(YELLOW)$<$(CLASSIC)"
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

check_compilation:
	@if [ -f $(NAME) ] && \
		[ -n "$(strip $(OBJS))" ] && \
		[ -z "$$(find $(SRCS) -newer $(NAME) 2>/dev/null)" ]; then \
		echo "$(BOLD)$(PURPLE)Tous les fichiers $(UNDERLINE)$(YELLOW)$(NAME)$(CLASSIC)$(BOLD)$(PURPLE) sont déjà compilés !$(CLASSIC)"; \
		exit 0; \
	fi

clean:
	@echo "$(BOLD)$(RED)"
	rm $(OBJS_DIR) -rf
	@echo "$(CLASSIC)"

fclean: clean
	@echo "$(BOLD)$(RED)"
	rm $(NAME) -f
	@echo "$(BOLD)$(GREEN)Tout a été supprimé... 🗑️\n$(CLASSIC)"

re: clean all

.PHONY: all clean fclean re
-include $(DEPS)
